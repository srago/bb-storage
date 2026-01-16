package blobstore

//
// BuildBarn blob access layer that stores metadata and small (<10MB) blobs in Spanner, while
// storing large blobs in a GCS bucket.  We update reference timestamps at insert time (in Put),
// at read time (in Get) and in FindMissing (to ensure blobs live long enough for a bazel build
// or test to complete).  We also prevent rows scheduled for deletion in Spanner from being
// returned by Get.
//
// New design requested by Ed to remove the use of the CompletenesssCheckingBlobAccess wrapper
// around the Spanner action cache:
//
// The original one-table approach is replaced by four tables: one for maintaining the CAS, one
// for holding AC entries, one holding associations between the two (foreign keys), and one used
// for implementing leader election (only one server should be handling evictions of stale blobs).
// The idea is to rely on the foreign keys to keep all of the CAS objects for a particular action
// alive as long as the action cache entry is alive.  Since GCS object lifetimes are unaffected by
// Spanner keys, we need to manage lifetimes in GCS ourselves.  Furthermore, we can't have a row
// deletion policy for CAS objects recorded in Spanner, because Spanner doesn't allow that unless
// we cascade deletes to the table holding the foreign key references -- that would remove the
// guarantee that as long as an action cache entry is valid, that all of the CAS objects it refers
// to are alive in the CAS.  We use the ReferenceTime field to detect inactive CAS blobs.
//
// We don't use a row deletion policy even for the action cache table, because we can't control when
// Spanner actually performs the deletions, which means we can't clean up the CAS as early as we could
// if we were to handle deletions of the stale action cache entries.  So we do that now, too.
//
// We use an LRU-like algorithm to reduce the frequency of ReferenceTime updates.  It has two arenas:
// one of objects that will expire in the configured timeframe, and one of objects that have been
// extended by having their reference times updated to the latest time they were referenced, but only
// when they have remained in the cache for half of their configured lifetimes.  This removes the need
// to update young objects that are accessed multiple times when they first enter the cache.  Similarly,
// when an object's reference time is updated, it will not receive further updates until it has spent
// an additional amount of time in the cache equal to half of the configured lifetime.
//
// We further reduce the frequency of ReferenceTime updates by skipping CAS ReferenceTime updates in Get
// when there is an action cache entry that refers to one of those blobs, because we update them when we
// update the ReferenceTime of the ActionCache entry that refers to them is read.

import (
	"context"
	"errors"
	"io"
	"log"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/buildbarn/bb-storage/pkg/blobstore/buffer"
	"github.com/buildbarn/bb-storage/pkg/blobstore/slicing"
	"github.com/buildbarn/bb-storage/pkg/capabilities"
	"github.com/buildbarn/bb-storage/pkg/digest"
	"github.com/buildbarn/bb-storage/pkg/util"

	"github.com/prometheus/client_golang/prometheus"

	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"

	"cloud.google.com/go/spanner"
	database "cloud.google.com/go/spanner/admin/database/apiv1"
	dbpb "cloud.google.com/go/spanner/admin/database/apiv1/databasepb"
	"cloud.google.com/go/storage"

	remoteexecution "github.com/bazelbuild/remote-apis/build/bazel/remote/execution/v2"
)

const (
	maxSpannerRecSz   int64 = 10*1024*1024 - 1
	maxMsgSz            int = 16 * 1024 * 1024
	maxTreeSz           int = 2 * 1024 * 1024
	acTableName             = "AC_Blobs_v1_0"
	casTableName            = "CAS_Blobs_v1_0"
	assocTableName          = "Assoc_v1_0"
	leaderTableName         = "Leader_v1_0"
	evicterSemId            = 1
	leaderTimeout		= 60 * 60 // 1 hour in seconds (eviction only runs once a day, so this is big enough to not waste too many cycles)
	defaultDaysToLive       = 14
	nsecsPerSec       int64	= 1000000000
	nsecsPerDay       int64 = nsecsPerSec * 60 * 60 * 24

	defaultEvictionElectionInterval = 30 * 60 // 30 minutes


	// Labels for backend metrics
	BE_SPANNER = "SPANNER"
	BE_GCS     = "GCS"

	// Operations on blobs
	BE_GET   = "GET"
	BE_DEL   = "DEL"
	BE_PUT   = "PUT"
	BE_FM    = "FINDMISSING"
	BE_TOUCH = "TOUCH"

	// Blob storage locations.
	// A bitmask makes it easier to support GCS-FUSE when we write small blobs everywhere.
	LOC_SPANNER = 0x01
	LOC_GCS	    = 0x02
)

var (
	spannerGCSCAS *spannerGCSBlobAccess
	spannerGCSBlobAccessPrometheusMetrics sync.Once

	spannerMalformedKeyCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "buildbarn",
			Subsystem: "blobstore",
			Name:      "spanner_malformed_key_total",
			Help:      "Number of keys that can't be parsed properly (should always be 0)",
		})
	gcsReftimeUpdateCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "buildbarn",
			Subsystem: "blobstore",
			Name:      "gcs_reftime_update_total",
			Help:      "Number of GCS object reference times updates have been attempted",
		})
	gcsReftimeUpdateFailedCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "buildbarn",
			Subsystem: "blobstore",
			Name:      "gcs_reftime_update_failed_total",
			Help:      "Number of GCS object reference times updates failed",
		})
	spannerReftimeUpdateCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "buildbarn",
			Subsystem: "blobstore",
			Name:      "spanner_reftime_update_total",
			Help:      "Number of spanner object reference times updates have been attempted",
		})
	spannerReftimeUpdateFailedCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "buildbarn",
			Subsystem: "blobstore",
			Name:      "spanner_reftime_update_failed_total",
			Help:      "Number of spanner object reference times updates failed",
		})
	spannerExpiredBlobReadIgnoredCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "buildbarn",
			Subsystem: "blobstore",
			Name:      "spanner_expired_blob_read_ignored_total",
			Help:      "Number of ignored read attempts of expired spanner blobs",
		})
	spannerDeleteActionCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "buildbarn",
			Subsystem: "blobstore",
			Name:      "spanner_delete_action_total",
			Help:      "Number of spanner action deletes that have been attempted",
		})
	spannerDeleteActionFailedCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "buildbarn",
			Subsystem: "blobstore",
			Name:      "spanner_delete_action_failed_total",
			Help:      "Number of spanner action deletes that have failed",
		})
	spannerDeleteBlobCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "buildbarn",
			Subsystem: "blobstore",
			Name:      "spanner_delete_blob_total",
			Help:      "Number of spanner blob deletes that have been attempted",
		})
	spannerDeleteBlobFailedCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "buildbarn",
			Subsystem: "blobstore",
			Name:      "spanner_delete_blob_failed_total",
			Help:      "Number of spanner blob deletes that have failed",
		})
	gcsDeleteBlobCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "buildbarn",
			Subsystem: "blobstore",
			Name:      "gcs_delete_blob_total",
			Help:      "Number of gcs blob deletes that have been attempted",
		})
	gcsDeleteBlobFailedCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "buildbarn",
			Subsystem: "blobstore",
			Name:      "gcs_delete_blob_failed_total",
			Help:      "Number of gcs blob deletes that have failed",
		})
	gcsFailedReadDeletedBlobCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "buildbarn",
			Subsystem: "blobstore",
			Name:      "gcs_failed_read_deleted_blob_total",
			Help:      "Number of deletes of GCS blobs that couldn't be read",
		})
	gcsFailedReadDeleteBlobFailedCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "buildbarn",
			Subsystem: "blobstore",
			Name:      "gcs_failed_read_delete_blob_failed_total",
			Help:      "Number of failed deletes of GCS blobs that couldn't be read",
		})
	gcsPutFailedContextCanceledCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "buildbarn",
			Subsystem: "blobstore",
			Name:      "gcs_put_failed_context_canceled_total",
			Help:      "Number of failed puts of GCS blobs because the context was canceled",
		})
	gcsPutFailedDeadlineExceededCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "buildbarn",
			Subsystem: "blobstore",
			Name:      "gcs_put_failed_deadline_exceeded_total",
			Help:      "Number of failed puts of GCS blobs because the deadline was exceeded",
		})
	gcsPutFailedOtherCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "buildbarn",
			Subsystem: "blobstore",
			Name:      "gcs_put_failed_other_total",
			Help:      "Number of failed puts of GCS blobs because of other reasons",
		})
	spannerMalformedBlobReadCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "buildbarn",
			Subsystem: "blobstore",
			Name:      "spanner_malformed_blob_deleted_total",
			Help:      "Number of malformed blobs that were deleted",
		},
		[]string{"backend_type"})
	backendOperationsDurationSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "buildbarn",
			Subsystem: "blobstore",
			Name:      "backend_operations_duration_seconds",
			Help:      "Amount of time spent per backend operation in seconds.",
			Buckets:   util.DecimalExponentialBuckets(-3, 6, 2),
		},
		[]string{"storage_type", "backend_type", "operation"})
)

type spannerGCSBlobAccess struct {
	capabilities.Provider

	spannerClient *spanner.Client
	gcsBucket     *storage.BucketHandle

	readBufferFactory ReadBufferFactory
	databaseName      string
	storageType       string
	daysToLive        uint64        // to avoid converting back and forth
	expirationAge     time.Duration // same as above, but easier for time calculations
	refUpdateThresh   time.Duration // when we start updating ReferenceTime
	serviceId         string
}

type spannerRecord struct {
	Key           string
	ReferenceTime time.Time
	InlineData    []byte
}

type assocRecord struct {
	ActionKey     string
	DigestKey     string
}

type leaderRecord struct {
	SemaphoreId       int64
	ServiceId         string
	ActivityTimestamp time.Time
}

// Keep track of keys and the storage locations where they reside.
type keyLoc struct {
	key	string
	loc	int
}

// Check if a Spanner table exists.  For the purpose of this exercise, if the query fails at all, we assume
// that the table doesn't exist.
func tableExists(ctx context.Context, cl *spanner.Client, tableName string) bool {
	stmt := spanner.NewStatement(`SELECT 1 FROM information_schema.tables WHERE table_name = "` + tableName + `"`)
	iter := cl.Single().Query(ctx, stmt)
	_, err := iter.Next()
	iter.Stop()
	log.Printf("spanner table %s check, err = %v", tableName, err)
	if err == nil {
		// Table exists.
		return true
	} else {
		// Either err is iterator.Done or some other error code.  In either case, we
		// assume that the table doesn't exist so the caller will try to create it.
		return false
	}
}

// databaseName is of the form "projects/<project ID>/instances/<instance name>/databases/<database name>".
func createSpannerTables(ctx context.Context, spannerClient *spanner.Client, databaseName string, daysToLive uint64) error {
	cl, err := database.NewDatabaseAdminClient(ctx)
	if err != nil {
		return util.StatusWrap(err, "Can't create spanner database admin client")
	}
	defer cl.Close()

	// If daysToLive is zero, use the default.
	if daysToLive == 0 {
		daysToLive = defaultDaysToLive
	}

	// If necessary, create the table for action cache entries.
	if !tableExists(ctx, spannerClient, acTableName) {
		// Table might not exist.  Try to create it.
		// NB: stay away from "CREATE TABLE IF NOT EXISTS" command because it is wicked slow
		s := `CREATE TABLE ` + acTableName + ` (
			Key STRING(MAX),
			ReferenceTime TIMESTAMP NOT NULL,
			InlineData BYTES(MAX),
		) PRIMARY KEY(Key)`
		op, err := cl.UpdateDatabaseDdl(ctx, &dbpb.UpdateDatabaseDdlRequest{
			Database: databaseName,
			Statements: []string{
				s,
			},
		})
		if err == nil {
			err = op.Wait(ctx)
		}
		if err != nil {
			// We could have raced with another pod.  Check again if the table exists.
			if !tableExists(ctx, spannerClient, acTableName) {
				return util.StatusWrapf(err, "Can't create spanner table %s", acTableName)
			}
		}
	}

	// If necessary, create the table for the CAS blobs.
	if !tableExists(ctx, spannerClient, casTableName) {
		// Table might not exist.  Try to create it.
		// NB: stay away from "CREATE TABLE IF NOT EXISTS" command because it is wicked slow
		s := `CREATE TABLE ` + casTableName + ` (
			Key STRING(MAX),
			ReferenceTime TIMESTAMP NOT NULL,
			InlineData BYTES(MAX),
		) PRIMARY KEY(Key)`
		op, err := cl.UpdateDatabaseDdl(ctx, &dbpb.UpdateDatabaseDdlRequest{
			Database: databaseName,
			Statements: []string{
				s,
			},
		})
		if err == nil {
			err = op.Wait(ctx)
		}
		if err != nil {
			// We could have raced with another pod.  Check again if the table exists.
			if !tableExists(ctx, spannerClient, casTableName) {
				return util.StatusWrapf(err, "Can't create spanner table %s", casTableName)
			}
		}
	}

	// If necessary, create the action cache table so that when an action cache entry is evicted by the delete policy,
	// all of the matching records in the Assoc table are removed.  However, we want to prevent the CAS blobs from being
	// removed until no more action cache entries refer to them, so we don't cascade deletes from the CAS table.  Attempts
	// to delete a CAS entry will fail if any action cache entries refer to it.
	if !tableExists(ctx, spannerClient, assocTableName) {
		// Table might not exist.  Try to create it.
		// NB: stay away from "CREATE TABLE IF NOT EXISTS" command because it is wicked slow
		s := `CREATE TABLE ` + assocTableName + ` (
			Key STRING(36) DEFAULT (GENERATE_UUID()),
			ActionKey STRING(MAX) NOT NULL,
			DigestKey STRING(MAX) NOT NULL,
			CONSTRAINT FKActionKey FOREIGN KEY(ActionKey) REFERENCES ` + acTableName + `(Key) ON DELETE CASCADE,
			CONSTRAINT FKDigestKey FOREIGN KEY(DigestKey) REFERENCES ` + casTableName + `(Key)
		) PRIMARY KEY(Key)`
		op, err := cl.UpdateDatabaseDdl(ctx, &dbpb.UpdateDatabaseDdlRequest{
			Database: databaseName,
			Statements: []string{
				s,
			},
		})
		if err == nil {
			err = op.Wait(ctx)
		}
		if err != nil {
			// We could have raced with another pod.  Check again if the table exists.
			if !tableExists(ctx, spannerClient, assocTableName) {
				return util.StatusWrapf(err, "Can't create spanner table %s", assocTableName)
			}
		}
	}

	// If necessary, create the table used for "leader election" -- we use it to decide which worker is in charge of
	// evicting stale entries in the action cache and CAS.
	if !tableExists(ctx, spannerClient, leaderTableName) {
		// Table might not exist.  Try to create it.
		// NB: stay away from "CREATE TABLE IF NOT EXISTS" command because it is wicked slow
		s := `CREATE TABLE ` + leaderTableName + ` (
			SemaphoreId INT64 NOT NULL,
			ServiceId STRING(1024) NOT NULL,
			ActivityTimestamp TIMESTAMP NOT NULL
		) PRIMARY KEY(SemaphoreId)`
		op, err := cl.UpdateDatabaseDdl(ctx, &dbpb.UpdateDatabaseDdlRequest{
			Database: databaseName,
			Statements: []string{
				s,
			},
		})
		if err == nil {
			err = op.Wait(ctx)
		}
		if err != nil {
			// We could have raced with another pod.  Check again if the table exists.
			if !tableExists(ctx, spannerClient, leaderTableName) {
				return util.StatusWrapf(err, "Can't create spanner table %s", leaderTableName)
			}
		}
	}

	return nil
}

func createGCSBucket(ctx context.Context, gcsBucket *storage.BucketHandle, databaseName string, daysToLive uint64) error {
	// Extract the project ID from the spanner database name (no, really).
	s := strings.Split(databaseName, "/")
	projectID := s[1]

	// Create the bucket.
	if err := gcsBucket.Create(ctx, projectID, nil); err != nil {
		return err
	}
	return nil
}

// Convert a digest to the key of the entry in the Spanner database and GCS bucket.
func (ba *spannerGCSBlobAccess) digestToKey(digest digest.Digest) string {
	sz := strconv.FormatInt(digest.GetSizeBytes(), 10)
	if ba.storageType == "AC" {
		// Instance names are hierarchical, but '/' has special meaning for GCS.
		// We don't need a hierarchical namespace for storage.
		instance := strings.ReplaceAll(digest.GetInstanceName().String(), "/", "-")
		return digest.GetHashString() + "-" + sz + "-" + instance
	} else if ba.storageType == "CAS" {
		return digest.GetHashString() + "-" + sz
	} else {
		panic("Invalid Spanner storage Type configured")
	}
}

func (ba *spannerGCSBlobAccess) findLocFromDigest(digest digest.Digest) int {
	var loc int
	if ba.storageType == "AC" {
		panic("Can't call fileLocFromDigest for Action Cache")
	}
	sz := digest.GetSizeBytes()
	if sz > maxSpannerRecSz {
		loc |= LOC_GCS
	} else {
		loc |= LOC_SPANNER
	}
	return loc
}

func (ba *spannerGCSBlobAccess) findLocFromKey(key string) (int, error) {
	if ba.storageType == "AC" {
		panic("Can't call fileLocFromKey for Action Cache")
	}
	s := strings.Split(key, "-")
	sz, err := strconv.ParseInt(s[1], 10, 64)
	if err != nil {
		return 0, err
	}
	var loc int
	if sz > maxSpannerRecSz {
		loc |= LOC_GCS
	} else {
		loc |= LOC_SPANNER
	}
	return loc, nil
}

func roundUpToDay(d time.Duration) time.Duration {
	return time.Duration(((int64(d) + nsecsPerDay - 1) / nsecsPerDay) * nsecsPerDay)
}

// NewSpannerGCSBlobAccess creates a BlobAccess that uses Spanner and GCS as its backing store.
func NewSpannerGCSBlobAccess(databaseName string, gcsBucketName string, readBufferFactory ReadBufferFactory, storageType string, expirationTime time.Duration,
	evictionElectionInterval time.Duration, evictionHostnameRegex string, capabilitiesProvider capabilities.Provider,
	clientOpts []option.ClientOption) (BlobAccess, error) {

	storageType = strings.ToUpper(storageType)

	// If expirationTime is zero, use the default.  Otherwise round it up to
	// an integral number of days.
	var daysToLive uint64
	if expirationTime == 0 {
		daysToLive = defaultDaysToLive
	} else {
		daysToLive = uint64(roundUpToDay(expirationTime) / time.Duration(nsecsPerDay))
	}
	expirationTime = time.Duration(daysToLive * uint64(nsecsPerDay))
	// The reference time update threshold is half of the expiration age
	log.Printf("daysToLive = %d, expirationTime = %d\n", daysToLive, expirationTime)

	spannerGCSBlobAccessPrometheusMetrics.Do(func() {
		prometheus.MustRegister(spannerMalformedKeyCount)
		prometheus.MustRegister(gcsReftimeUpdateCount)
		prometheus.MustRegister(gcsReftimeUpdateFailedCount)
		prometheus.MustRegister(spannerReftimeUpdateCount)
		prometheus.MustRegister(spannerReftimeUpdateFailedCount)
		prometheus.MustRegister(spannerMalformedBlobReadCount)
		prometheus.MustRegister(spannerExpiredBlobReadIgnoredCount)
		prometheus.MustRegister(spannerDeleteActionCount)
		prometheus.MustRegister(spannerDeleteActionFailedCount)
		prometheus.MustRegister(spannerDeleteBlobCount)
		prometheus.MustRegister(spannerDeleteBlobFailedCount)
		prometheus.MustRegister(gcsDeleteBlobCount)
		prometheus.MustRegister(gcsDeleteBlobFailedCount)
		prometheus.MustRegister(gcsFailedReadDeletedBlobCount)
		prometheus.MustRegister(gcsFailedReadDeleteBlobFailedCount)
		prometheus.MustRegister(gcsPutFailedContextCanceledCount)
		prometheus.MustRegister(gcsPutFailedDeadlineExceededCount)
		prometheus.MustRegister(gcsPutFailedOtherCount)
		prometheus.MustRegister(backendOperationsDurationSeconds)
	})

	ctx := context.Background()
	cfg := spanner.ClientConfig {
		DisableNativeMetrics: true,
	}
	spannerClient, err := spanner.NewClientWithConfig(ctx, databaseName, cfg)
	if err != nil {
		return nil, util.StatusWrap(err, "Can't create spanner client")
	}

	// If the spanner tables don't exist, create them.
	if err = createSpannerTables(ctx, spannerClient, databaseName, daysToLive); err != nil {
		spannerClient.Close()
		return nil, util.StatusWrap(err, "Can't create spanner table")
	}

	// Initialize the leader election row for eviction if it doesn't already exist.
	rec := leaderRecord{
		SemaphoreId:       evicterSemId,
		ServiceId:         "NONE",
		ActivityTimestamp: time.Unix(0, 0),
	}
	insertMut, err := spanner.InsertStruct(leaderTableName, rec)
	if err != nil {
		return nil, util.StatusWrapfWithCode(err, codes.Internal, "Can't create mutation for leader election initialization")
	}
	start := time.Now()
	_, err = spannerClient.Apply(ctx, []*spanner.Mutation{insertMut})
	backendOperationsDurationSeconds.WithLabelValues(storageType, BE_SPANNER, BE_PUT).Observe(time.Now().Sub(start).Seconds())
	if err != nil && status.Code(err) != codes.AlreadyExists {
		return nil, util.StatusWrapfWithCode(err, codes.Internal, "Can't apply mutation for leader election initialization")
	}

	storageClient, err := storage.NewClient(ctx, clientOpts...)
	if err != nil {
		spannerClient.Close()
		return nil, util.StatusWrap(err, "Can't create GCS client")
	}
	gcsBucket := storageClient.Bucket(gcsBucketName)

	// If the GCS bucket doesn't exist, create it.
	_, err = gcsBucket.Attrs(ctx)
	if errors.Is(err, storage.ErrBucketNotExist) {
		err = createGCSBucket(ctx, gcsBucket, databaseName, daysToLive)
		if err != nil {
			// We could have raced with another pod.  Check if the bucket exists.
			_, xerr := gcsBucket.Attrs(ctx)
			if errors.Is(xerr, storage.ErrBucketNotExist) {
				// Bucket still doesn't exist.
				spannerClient.Close()
				storageClient.Close()
				return nil, util.StatusWrap(err, "Can't create GCS bucket")
			}
		}
	} else if err != nil {
		spannerClient.Close()
		storageClient.Close()
		return nil, util.StatusWrap(err, "Can't access GCS bucket")
	}

	log.Printf("NewSpannerGCSBlobAccess type %s", storageType)

	node := os.Getenv("NODE_NAME")
	id := os.Getenv("HOSTNAME")
	ba := &spannerGCSBlobAccess{
		Provider:      capabilitiesProvider,
		spannerClient: spannerClient,
		gcsBucket:     gcsBucket,

		readBufferFactory: readBufferFactory,
		databaseName:      databaseName,
		storageType:       storageType,
		daysToLive:        daysToLive,
		expirationAge:     expirationTime,
		refUpdateThresh:   expirationTime / time.Duration(2),  // half of the expiration age
		serviceId:         node + "-" + id,
	}
	if storageType == "CAS" {
		spannerGCSCAS = ba
	} else {
		match, err := regexp.Match(evictionHostnameRegex, []byte(id))
		// One pod gets to handle evictions.  Handle multiple clusters sharing the same set of tables by
		// including the node name in the serviceId used in leader election.
		if err == nil && match {
			if evictionElectionInterval == time.Duration(0) {
				evictionElectionInterval =  time.Duration(defaultEvictionElectionInterval) * time.Second
			}
			electionInterval := uint64(evictionElectionInterval / time.Duration(nsecsPerSec))
			go ba.periodicEvicter(electionInterval)
		}
	}
	return ba, nil
}

func (ba *spannerGCSBlobAccess) Get(ctx context.Context, digest digest.Digest) buffer.Buffer {
	if err := util.StatusFromContext(ctx); err != nil {
		return buffer.NewBufferFromError(err)
	}
	key := ba.digestToKey(digest)

	var tableName string
	if ba.storageType == "AC" {
		tableName = acTableName
	} else {
		tableName = casTableName
	}

	// Grab the row itself
	start := time.Now()
	now := start.UTC()
	row, err := ba.spannerClient.Single().ReadRow(ctx, tableName, spanner.Key{key}, []string{"ReferenceTime", "InlineData"})
	backendOperationsDurationSeconds.WithLabelValues(ba.storageType, BE_SPANNER, BE_GET).Observe(time.Now().Sub(start).Seconds())
	if err != nil {
		return buffer.NewBufferFromError(util.StatusWrapfWithCode(err, codes.NotFound, "GET error: ReadRow key %s failed", key))
	}

	var s struct {
		ReferenceTime time.Time
		InlineData    []byte
	}
	err = row.ToStruct(&s)
	if err != nil {
		return buffer.NewBufferFromError(util.StatusWrapfWithCode(err, codes.Internal, "GET error: ToStruct key %s failed", key))
	}

	var loc int
	if len(s.InlineData) == 0 {
		loc |= LOC_GCS
	} else {
		loc |= LOC_SPANNER
	}

	// Exclude expired blobs -- they don't exist anymore; we're waiting for the eviction background thread to delete them.
	//
	// When we update the reference time of an AC entry, we also update the referencetime of all CAS blobs for which it has
	// foreign key references.  This maintains the invariant that a CAS blob's reference time is always >= to the reference
	// times of all AC entries that reference the blob.  Thus, if the blob is expired, there should be no AC entries that
	// refer to it.
	if !now.Before(s.ReferenceTime.Add(ba.expirationAge)) {
		spannerExpiredBlobReadIgnoredCount.Inc()
		return buffer.NewBufferFromError(status.Error(codes.NotFound, "Blob not found"))
	}

	validationFunc := func(dataIsValid bool) {
		if !dataIsValid {
			var beType string
			if (loc & LOC_GCS) != 0 {
				beType = BE_GCS
			} else {
				beType = BE_SPANNER
			}
			spannerMalformedBlobReadCount.WithLabelValues(beType).Inc()
		}
	}

	var b buffer.Buffer
	if (loc & LOC_GCS) != 0 {
		// We gotta go get it from GCS
		obj := ba.gcsBucket.Object(key)

		r, err := obj.NewReader(ctx)
		if err != nil {
			return buffer.NewBufferFromError(err)
		}
		b = ba.readBufferFactory.NewBufferFromReader(digest, r, validationFunc)
		b = buffer.WithErrorHandler(
			b,
			&spannerGCSErrorHandler{
				start:  time.Now(),
				sType:  ba.storageType,
				beType: BE_GCS,
				op:     BE_GET,
			})
	} else {
		// It's inline, so return it directly
		b = ba.readBufferFactory.NewBufferFromByteSlice(digest, s.InlineData, validationFunc)
	}
	_, err = b.GetSizeBytes()
	if err != nil {
		return buffer.NewBufferFromError(util.StatusWrapfWithCode(err, codes.Internal, "GET error: key %s, type %v", key, ba.storageType))
	}
	if now.After(s.ReferenceTime.Add(ba.refUpdateThresh)) {
		if ba.storageType == "AC" {
			// Update the ReferenceTime of the AC entry and of all CAS blobs this AC entry refers to.
			go func() {
				ctx := context.Background()
				keys := []string{key}
				go ba.touchSpannerObjects(ctx, tableName, keys, now)

				stmt := spanner.NewStatement(`SELECT DigestKey FROM ` + assocTableName + ` WHERE ActionKey = @key`)
				stmt.Params["key"] = key
				start := time.Now()
				iter := spannerGCSCAS.spannerClient.Single().Query(ctx, stmt)
				defer iter.Stop()
				backendOperationsDurationSeconds.WithLabelValues("CAS", BE_SPANNER, BE_TOUCH).Observe(time.Now().Sub(start).Seconds())
				keysToTouch := make([]string, 0, 128)
				i := 0
				for {
					var dkey string
					row, err := iter.Next()
					if err == iterator.Done {
						break
					}
					i++
					if err != nil {
						log.Printf("ERROR: query iterator row %d, got %v", i, err)
						break
					}
					err = row.Column(0, &dkey)
					if err != nil {
						log.Printf("ERROR: row %d, column 0 wanted Key, got %v", i, err)
					} else if dkey != "" {
						keysToTouch = append(keysToTouch, dkey)
					}
				}
				if len(keysToTouch) != 0 {
					go spannerGCSCAS.touchSpannerObjects(context.Background(), casTableName, keysToTouch, now)
				}
			}()
		} else if !ba.isCoveredByAction(ctx, key) {
			keys := []string{key}
			go ba.touchSpannerObjects(context.Background(), tableName, keys, now)
		}
	}
	return b
}

func (ba *spannerGCSBlobAccess) Put(ctx context.Context, digest digest.Digest, b buffer.Buffer) error {
	if err := util.StatusFromContext(ctx); err != nil {
		b.Discard()
		return err
	}

	// If we're bigger than 10MB, we have to offload to GCS
	size, err := b.GetSizeBytes()
	if err != nil {
		b.Discard()
		return util.StatusWrapfWithCode(err, codes.Internal, "Put Blob %v: can't get size", digest)
	}

	key := ba.digestToKey(digest)

	var digestKeys []string
	if ba.storageType == "AC" {
		// Calculate list of hashes in merkle tree so we can add them to the Assoc table
		b1, b2 := b.CloneCopy(maxMsgSz)
		actionResult, err := b1.ToProto(&remoteexecution.ActionResult{}, maxMsgSz)
		if err != nil {
			b2.Discard()
			return util.StatusWrap(err, "Can't convert ActionResult")
		}

		digestKeys, err = ba.getDigestKeysFromActionResult(ctx, digest.GetDigestFunction(), actionResult.(*remoteexecution.ActionResult))
		if err != nil {
			b2.Discard()
			return util.StatusWrap(err, "Can't get dependent blobs from ActionResult")
		}
		b = b2
	}

	var inlineData []byte = nil
	now := time.Now().UTC()
	if size > maxSpannerRecSz {
		obj := ba.gcsBucket.Object(key)
		w := obj.NewWriter(ctx)
		start := time.Now()
		var err error
		if _, err = io.Copy(w, b.ToReader()); err == nil {
			if err = w.Close(); err != nil {
				log.Printf("Blob %s can't be copied to GCS, close failed: %v", key, err)
			}
		} else {
			log.Printf("Blob %s can't be copied to GCS, write failed: %v", key, err)
		}
		backendOperationsDurationSeconds.WithLabelValues(ba.storageType, BE_GCS, BE_PUT).Observe(time.Now().Sub(start).Seconds())
		if err != nil {
			if errors.Is(err, context.Canceled) || status.Code(err) == codes.Canceled {
				gcsPutFailedContextCanceledCount.Inc()
			} else if errors.Is(err, context.DeadlineExceeded) || status.Code(err) == codes.DeadlineExceeded {
				gcsPutFailedDeadlineExceededCount.Inc()
			} else {
				gcsPutFailedOtherCount.Inc()
			}
			return err
		}
		inlineData = nil
	} else {
		inlineData, err = b.ToByteSlice(int(maxSpannerRecSz))
		if err != nil {
			return util.StatusWrapfWithCode(err, codes.Internal, "Blob %s can't be copied to Spanner", key)
		}
		if len(inlineData) == 0 {
			log.Printf("WARNING: ByteSlice size is 0, expected %d, key %s", size, key)
		}
	}

	// Now insert into the spanners no matter what!
	rec := spannerRecord{
		Key:           key,
		ReferenceTime: now.Truncate(time.Second),
		InlineData:    inlineData,
	}

	var tableName string
	if ba.storageType == "AC" {
		tableName = acTableName
	} else {
		tableName = casTableName
	}

	insertMut, err := spanner.InsertOrUpdateStruct(tableName, rec)
	if err != nil {
		return util.StatusWrapfWithCode(err, codes.Internal, "Can't create mutation for Blob %s", key)
	}

	start := time.Now()
	_, err = ba.spannerClient.Apply(ctx, []*spanner.Mutation{insertMut})
	backendOperationsDurationSeconds.WithLabelValues(ba.storageType, BE_SPANNER, BE_PUT).Observe(time.Now().Sub(start).Seconds())
	if err != nil {
		return util.StatusWrapfWithCode(err, codes.Internal, "Can't apply mutation for Blob %s", key)
	}

	if ba.storageType == "AC" {
		// If this is an overwrite, remove any entries for this AC entry from the Assoc table
		ba.deleteAssociationsFromSpanner(ctx, key)
		// Add new entries to the Assoc table
		if digestKeys != nil && len(digestKeys) != 0 {
			ba.addAssociationsToSpanner(ctx, key, digestKeys, now)
		}
	}
	return nil
}

// This function is only supported for CAS objects.
func (ba *spannerGCSBlobAccess) FindMissing(ctx context.Context, digests digest.Set) (digest.Set, error) {
	if err := util.StatusFromContext(ctx); err != nil {
		return digest.EmptySet, err
	}
	if digests.Empty() {
		return digest.EmptySet, nil
	}
	// This funciton isn't supported for the action cache.
	if ba.storageType == "AC" {
		return digest.EmptySet, status.Error(codes.Unimplemented, "Bazel action cache does not support bulk existence checking")
	}

	keyToDigest := make(map[string]digest.Digest, digests.Length()) // Needed for timestamp updates
	ksl := make([]string, digests.Length())                         // Needed for the query
	for _, digest := range digests.Items() {
		k := ba.digestToKey(digest)
		keyToDigest[k] = digest
		ksl = append(ksl, k)
	}

	// We want to grab anything not in the CAS Blobs table.  First find what's there so we can exclude them from the
	// list of missing blobs.  Then decide which of the existing ones need their reftime to be updated.
	stmt := spanner.NewStatement(`SELECT Key, ReferenceTime FROM ` + casTableName + ` WHERE Key IN UNNEST(@keys) and TIMESTAMP_DIFF(CURRENT_TIMESTAMP(), ReferenceTime, DAY) < @expdays`)
	stmt.Params["keys"] = ksl
	stmt.Params["expdays"] = int64(ba.daysToLive)
	start := time.Now()
	iter := ba.spannerClient.Single().Query(ctx, stmt)
	defer iter.Stop()
	backendOperationsDurationSeconds.WithLabelValues("CAS", BE_SPANNER, BE_FM).Observe(time.Now().Sub(start).Seconds())

	missing := digest.NewSetBuilder()
	keysToTouch := make([]string, 0, digests.Length())
	now := time.Now().UTC()
	i := 0
	for {
		var key string
		var refTime time.Time
		row, err := iter.Next()  // Don't return errors from this scope -- let bazel re-upload the blobs as if they were missing
		if err == iterator.Done {
			break
		}
		i++
		if err != nil {
			log.Printf("ERROR: query iterator row %d, got %v", i, err)
			break
		}
		err = row.Column(0, &key)
		if err != nil {
			log.Printf("ERROR: row %d, column 0 wanted Key, got %v", i, err)
			continue
		}
		err = row.Column(1, &refTime)
		if err != nil {
			log.Printf("ERROR Column 1 wanted ReferenceTime, got %v", err)
			continue
		}
		if key != "" && now.After(refTime.Add(ba.refUpdateThresh)) {
			keysToTouch = append(keysToTouch, key)
		}
		delete(keyToDigest, key)
	}

	// Now keyToDigest consists only of missing blobs.  Prepare the missing digest set to return to the caller.
	for _, digest := range keyToDigest {
		missing.Add(digest)
	}

	// Now update the ReferenceTime field for the Spanner blobs we have.  GCS blobs also have records in spanner to make FindMissing
	// efficient and prevent large CAS blobs from being evicted before any action cache entries that reference them.
	if len(keysToTouch) != 0 {
		ba.touchSpannerObjects(context.Background(), casTableName, keysToTouch, now)
	}

	return missing.Build(), nil
}

func (ba *spannerGCSBlobAccess) GetFromComposite(ctx context.Context, parentDigest, childDigest digest.Digest, slicer slicing.BlobSlicer) buffer.Buffer {
	b, _ := slicer.Slice(ba.Get(ctx, parentDigest), childDigest)
	return b
}

// Update the ReferenceTime field the Spanner blob.
func (ba *spannerGCSBlobAccess) touchSpannerObjects(ctx context.Context, tableName string, keys []string, t time.Time) {
	spannerReftimeUpdateCount.Inc()
	start := time.Now()
	ba.spannerClient.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		// Hopefully this is more efficient than doing a read-modify-write.  Tried InsertOrUpdateStruct(),
		// but that set the InlineData field to NULL, contradicting the manual page that "Any column values
		// not explicitly written are preserved."
		stmt := spanner.NewStatement(`UPDATE ` + tableName + ` SET ReferenceTime = TIMESTAMP(@reftime) WHERE Key in unnest(@keys)`)
		stmt.Params["keys"] = keys
		stmt.Params["reftime"] = t.Format(time.RFC3339)
		_, err := txn.Update(ctx, stmt)
		if err != nil {
			spannerReftimeUpdateFailedCount.Inc()
			log.Printf("Can't update reftime in %d Blobs: %v", len(keys), err)
			return err
		}
		return nil
	})
	backendOperationsDurationSeconds.WithLabelValues(ba.storageType, BE_SPANNER, BE_TOUCH).Observe(time.Now().Sub(start).Seconds())
}

func (ba *spannerGCSBlobAccess) deleteAssociationsFromSpanner(ctx context.Context, key string) {
	start := time.Now()
	ba.spannerClient.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		stmt := spanner.NewStatement(`DELETE FROM ` + assocTableName + ` WHERE ActionKey = @key`)
		stmt.Params["key"] = key
		_, err := txn.Update(ctx, stmt)
		if err != nil {
			log.Printf("Can't remove associations for AC key %s: %v", key, err)
			return err
		}
		return nil
	})
	backendOperationsDurationSeconds.WithLabelValues(ba.storageType, BE_SPANNER, BE_DEL).Observe(time.Now().Sub(start).Seconds())
}

func (ba *spannerGCSBlobAccess) addAssociationsToSpanner(ctx context.Context, key string, digestKeys []string, now time.Time) {
	var assocRecs []assocRecord
	assocRecs = make([]assocRecord, len(digestKeys))
	for idx, _ := range digestKeys {
		assocRecs[idx].ActionKey = key
		assocRecs[idx].DigestKey = digestKeys[idx]
	}
	start := time.Now()
	ba.spannerClient.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		stmt := spanner.NewStatement(`INSERT INTO ` + assocTableName + ` (ActionKey, DigestKey) SELECT * FROM UNNEST(@assocRecs)`)
		stmt.Params["assocRecs"] = assocRecs
		_, err := txn.Update(ctx, stmt)
		if err != nil {
			spannerReftimeUpdateFailedCount.Inc()
			log.Printf("Can't add associations for action %s: %v", key, err)
			return err
		}
		return nil
	})
	backendOperationsDurationSeconds.WithLabelValues(ba.storageType, BE_SPANNER, BE_TOUCH).Observe(time.Now().Sub(start).Seconds())
	// Because this is part of adding associations to the Assoc table, no need to check refUpdateThresh.  This ensures that
	// every CAS object referenced by an action is no older than any action.  This helps to avoid attempting to evict CAS
	// blobs that are still referenced by an action cache entry.
	ba.touchSpannerObjects(ctx, casTableName, digestKeys, now)
}

func (ba *spannerGCSBlobAccess) isCoveredByAction(ctx context.Context, key string) bool {
	if ba.storageType == "AC" {
		panic("Can't call isCoveredByAction by Action Cache")
	}
	stmt := spanner.NewStatement(`SELECT ActionKey FROM ` + assocTableName + ` WHERE DigestKey = @key`)
	stmt.Params["key"] = key
	start := time.Now()
	iter := ba.spannerClient.Single().Query(ctx, stmt)
	defer iter.Stop()
	backendOperationsDurationSeconds.WithLabelValues(ba.storageType, BE_SPANNER, BE_TOUCH).Observe(time.Now().Sub(start).Seconds())
	covered := false

	// We don't need to iterate through all of the rows.  We just need to know if any AC entry refers to this CAS key
	for {
		_, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err == nil {
			covered = true
			break
		}
	}
	return covered
}

//
// Periodically do leader election.  Every 24 hours (ish) the leader will evict stale AC entries and CAS blobs.
// Note that election interval is in seconds.
//
func (ba *spannerGCSBlobAccess) periodicEvicter(electionInterval uint64) {
	log.Printf("serviceId is %s", ba.serviceId)
	err := tryLeaderElection(context.Background(), ba.spannerClient, evicterSemId, ba.serviceId, leaderTimeout)
	if err != nil {
		log.Printf("Eviction: leader election failed: %v", err)
	}
	t1 := time.NewTimer(time.Duration(electionInterval) * time.Second)  // leader election frequency
	t2 := time.NewTimer(time.Duration((2 * electionInterval) + leaderTimeout) * time.Second)  // time before first check for evictions, allows for leader election to complete after pod deployment
	for {
		select {
		case <-t1.C:
			t1.Stop()
			t1 = time.NewTimer(time.Duration(electionInterval) * time.Second)
			err := tryLeaderElection(context.Background(), ba.spannerClient, evicterSemId, ba.serviceId, leaderTimeout)
			if err != nil {
				log.Printf("Eviction: leader election failed: %v", err)
			}

		case <-t2.C:
			t2.Stop()
			t2 = time.NewTimer(24 * time.Hour)
			serviceId, err := queryLeader(context.Background(), ba.spannerClient, evicterSemId, leaderTimeout)
			if err != nil {
				log.Printf("Eviction: can't determine leader: %v", err)
			} else if serviceId == "" {
				log.Printf("Eviction: no leader found")
			} else if (serviceId == ba.serviceId) {
				log.Printf("I am the Evicter!")
				ba.evictStaleACBlobs()
				spannerGCSCAS.evictStaleCASBlobs()
			}
		}


	}
}

func (ba *spannerGCSBlobAccess) evictStaleACBlobs() {
	// We want to find all stale entries in the action cache and then delete them.
	log.Printf("Starting Evictions...")
	cfg := spanner.ClientConfig {
		DisableNativeMetrics: true,
	}
	cl, err := spanner.NewClientWithConfig(context.Background(), ba.databaseName, cfg)
	if err != nil {
		log.Printf("Can't create a spanner client: %v", err)
		return
	}
	defer cl.Close()
	d := time.Now().Add(time.Duration(600 * nsecsPerSec))
	ctx, cancel := context.WithDeadline(context.Background(), d)
	defer cancel()
	start := time.Now()
	// TODO(ragost): what if this thing is a large blob?  Can this happen?
	stmt := spanner.NewStatement(`DELETE FROM ` + acTableName +
		` WHERE TIMESTAMP_DIFF(CURRENT_TIMESTAMP(), ReferenceTime, DAY) >= @expdays`)
	stmt.Params["expdays"] = int64(ba.daysToLive)
	count, err := cl.PartitionedUpdate(ctx, stmt)
	if err != nil {
		// We don't have the number of failed deletes, so can't increment metric
		log.Printf("Problems evicting AC entries: %v", err)
	}
	backendOperationsDurationSeconds.WithLabelValues(ba.storageType, BE_SPANNER, BE_DEL).Observe(time.Now().Sub(start).Seconds())
	spannerDeleteActionCount.Add(float64(count))
	log.Printf("Evicted %d entries from the AC", count)
}

func (ba *spannerGCSBlobAccess) evictStaleCASBlobs() {
	// We want to find all stale entries in the CAS and then delete them.  Start with the small blobs.
	cfg := spanner.ClientConfig {
		DisableNativeMetrics: true,
	}
	cl, err := spanner.NewClientWithConfig(context.Background(), ba.databaseName, cfg)
	if err != nil {
		log.Printf("Can't create a spanner client: %v", err)
		return
	}
	defer cl.Close()
	d := time.Now().Add(time.Duration(600 * nsecsPerSec))
	ctx, cancel := context.WithDeadline(context.Background(), d)
	defer cancel()
	start := time.Now()
	// If a CAS blob hasn't been referenced in the configured lifetime, then by definition there can't be
	// any AC entries that reference it, because we just killed all of the stale AC entries.
	stmt := spanner.NewStatement(`DELETE FROM ` + casTableName +
		` WHERE TIMESTAMP_DIFF(CURRENT_TIMESTAMP(), ReferenceTime, DAY) >= @expdays AND InlineData IS NOT NULL`)
	stmt.Params["expdays"] = int64(ba.daysToLive)
	count, err := cl.PartitionedUpdate(ctx, stmt)
	if err != nil {
		// We don't have the number of failed deletes, so can't increment metric
		log.Printf("Problems evicting small Blobs: %v", err)
	}
	backendOperationsDurationSeconds.WithLabelValues(ba.storageType, BE_SPANNER, BE_DEL).Observe(time.Now().Sub(start).Seconds())
	spannerDeleteBlobCount.Add(float64(count))
	log.Printf("Evicted %d small blobs from the CAS", count)

	// Now delete the stale large Blobs.  First we need to get a list of the keys so we can delete them from GCS.
	// NB: there are far fewer large Blobs than small ones, so nothing too fancy here.
	d = time.Now().Add(time.Duration(600 * nsecsPerSec))
	ctx, cancel = context.WithDeadline(context.Background(), d)
	defer cancel()
	stmt = spanner.NewStatement(`SELECT Key FROM ` + casTableName + ` WHERE TIMESTAMP_DIFF(CURRENT_TIMESTAMP(), ReferenceTime, DAY) >= @expdays AND InlineData IS NULL`)
	stmt.Params["expdays"] = int64(ba.daysToLive)
	start = time.Now()
	iter := ba.spannerClient.Single().Query(ctx, stmt)
	defer iter.Stop()

	keys := make([]string, 0, 1000)
	i := 0
	for {
		// Errors in this function (interpretting the row results) should only occur if someone changes the
		// schema without updating this file.
		var key string
		var row *spanner.Row
		row, err = iter.Next()
		if err == iterator.Done {
			break
		}
		i++
		if err != nil {
			log.Printf("ERROR: query iterator row %d, got %v", i, err)
			continue
		}
		err = row.Column(0, &key)
		if err != nil {
			log.Printf("ERROR: row %d, column 0 wanted Key, got %v", i, err)
		} else if key != "" {
			keys = append(keys, key)
		}
	}
	backendOperationsDurationSeconds.WithLabelValues(ba.storageType, BE_SPANNER, BE_DEL).Observe(time.Now().Sub(start).Seconds())

	if err != nil && err != iterator.Done {
		log.Printf("Can't evict large Blobs: %v", err)
	}

	if len(keys) == 0 {
		log.Printf("Evicted 0 large blobs from the CAS")
		return
	}

	// To avoid racing with clients uploading the same CAS blob that we're trying to evict, we still rely on the reference
	// time to prevent us from deleting an instance of the reloaded blob. 
	d = time.Now().Add(time.Duration(600 * nsecsPerSec))
	ctx, cancel = context.WithDeadline(context.Background(), d)
	defer cancel()
	start = time.Now()
	stmt = spanner.NewStatement(`DELETE FROM ` + casTableName +
		` WHERE Key IN UNNEST(@keys) AND TIMESTAMP_DIFF(CURRENT_TIMESTAMP(), ReferenceTime, DAY) >= @expdays`)
	stmt.Params["keys"] = keys
	stmt.Params["expdays"] = int64(ba.daysToLive)
	_, err = ba.spannerClient.PartitionedUpdate(ctx, stmt)
	backendOperationsDurationSeconds.WithLabelValues(ba.storageType, BE_SPANNER, BE_DEL).Observe(time.Now().Sub(start).Seconds())
	if err != nil {
		log.Printf("Problem evicting large Blobs: %v", err)
		return
	}

	// Now we need to check if any of the keys we found in the SELECT above still exist in the CAS table so we can avoid
	// deleting them in GCS.
	d = time.Now().Add(time.Duration(600 * nsecsPerSec))
	ctx, cancel = context.WithDeadline(context.Background(), d)
	defer cancel()
	start = time.Now()
	stmt = spanner.NewStatement(`SELECT Key FROM ` + casTableName + ` WHERE Key IN UNNEST(@keys)`)
	stmt.Params["keys"] = keys
	iter = ba.spannerClient.Single().Query(ctx, stmt)
	backendOperationsDurationSeconds.WithLabelValues(ba.storageType, BE_GCS, BE_DEL).Observe(time.Now().Sub(start).Seconds())
	i = 0
	for {
		var key string
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		i++
		if err != nil {
			log.Printf("ERROR: query iterator row %d, got %v", i, err)
			continue
		}
		err = row.Column(0, &key)
		if err != nil {
			log.Printf("ERROR: row %d, column 0 wanted Key, got %v", i, err)
		} else if key != "" {
			log.Printf("Raced with deleting large CAS blob, key %s; not deleting it from GCS", key)
			keys = slices.DeleteFunc(keys, func(s string) bool {
				return s == key
			})
		}
	}

	if len(keys) == 0 {
		log.Printf("Evicted 0 large blobs from the CAS after accounting for races")
		return
	}

	errDel := 0
	// Finally remove the large blobs from GCS.
	d = time.Now().Add(time.Duration(600 * nsecsPerSec))
	ctx, cancel = context.WithDeadline(context.Background(), d)
	defer cancel()
	for _, key := range keys {
		object := ba.gcsBucket.Object(key)
		start := time.Now()
		err = object.Delete(ctx)
		backendOperationsDurationSeconds.WithLabelValues(ba.storageType, BE_GCS, BE_DEL).Observe(time.Now().Sub(start).Seconds())
		if err != nil {
			log.Printf("Can't evict large Blob %s: %v", key, err)
			errDel++
			gcsDeleteBlobFailedCount.Inc()
		} else {
			gcsDeleteBlobCount.Inc()
		}
	}
	log.Printf("Evicted %d large blobs from the CAS", len(keys) - errDel)
}

type spannerGCSErrorHandler struct {
	start  time.Time
	sType  string
	beType string
	op     string
}

func (eh *spannerGCSErrorHandler) OnError(err error) (buffer.Buffer, error) {
	return nil, err
}

func (eh *spannerGCSErrorHandler) Done() {
	backendOperationsDurationSeconds.WithLabelValues(eh.sType, eh.beType, eh.op).Observe(time.Now().Sub(eh.start).Seconds())
}

type digestKeys struct {
	keys       []string
	digestFunc digest.Function
}

// Most of this following logic is borrowed from CompletenessCheckingBlobAccess.
func (ba *spannerGCSBlobAccess) getDigestKeysFromActionResult(ctx context.Context, digestFunc digest.Function, actionResult *remoteexecution.ActionResult) ([]string, error) {
	dk := &digestKeys{}
	dk.keys = make([]string, 0, 128)
	dk.digestFunc = digestFunc

	// Iterate over all remoteexecution.Digest fields contained
	// within the ActionResult. Check the existence of output
	// directories, even though they are loaded through GetTree()
	// later on. GetTree() may not necessarily cause those objects
	// to be touched.
	for _, outputFile := range actionResult.OutputFiles {
		if err := dk.add(outputFile.Digest); err != nil {
			return nil, err
		}
	}
	for _, outputDirectory := range actionResult.OutputDirectories {
		if err := dk.add(outputDirectory.TreeDigest); err != nil {
			return nil, err
		}
		if err := dk.add(outputDirectory.RootDirectoryDigest); err != nil {
			return nil, err
		}
	}
	if err := dk.add(actionResult.StdoutDigest); err != nil {
		return nil, err
	}
	if err := dk.add(actionResult.StderrDigest); err != nil {
		return nil, err
	}

	// Iterate over all remoteexecution.Digest fields contained
	// within output directories (remoteexecution.Tree objects)
	// referenced by the ActionResult.
	remainingTreeSizeBytes := int64(maxTreeSz)
	for _, outputDirectory := range actionResult.OutputDirectories {
		treeDigest, err := dk.deriveDigest(outputDirectory.TreeDigest)
		if err != nil {
			return nil, err
		}
		sizeBytes := treeDigest.GetSizeBytes()
		if sizeBytes > remainingTreeSizeBytes {
			return nil, status.Errorf(codes.NotFound, "Combined size of all output directories exceeds maximum limit of %d bytes", maxTreeSz)
		}
		remainingTreeSizeBytes -= sizeBytes

		r := spannerGCSCAS.Get(ctx, treeDigest).ToReader()
		if err := util.VisitProtoBytesFields(r, func(fieldNumber protowire.Number, offsetBytes, sizeBytes int64, fieldReader io.Reader) error {
			if fieldNumber == TreeRootFieldNumber || fieldNumber == TreeChildrenFieldNumber {
				directoryMessage, err := buffer.NewProtoBufferFromReader(
					&remoteexecution.Directory{},
					io.NopCloser(fieldReader),
					buffer.UserProvided,
				).ToProto(&remoteexecution.Directory{}, maxMsgSz)
				if err != nil {
					return err
				}
				directory := directoryMessage.(*remoteexecution.Directory)

				// Files are always stored as separate CAS
				// objects. Directories should only be stored
				// as separate CAS objects if we announce them
				// to be present by having the root directory
				// digest set.
				for _, child := range directory.Files {
					if err := dk.add(child.Digest); err != nil {
						return err
					}
				}
				if outputDirectory.RootDirectoryDigest != nil {
					for _, child := range directory.Directories {
						if err := dk.add(child.Digest); err != nil {
							return err
						}
					}
				}
			}
			return nil
		}); err != nil {
			// Any errors generated above may be caused by
			// data corruption on the Tree object. Force
			// reading the Tree until completion, and prefer
			// read errors over any errors generated above.
			if _, copyErr := io.Copy(io.Discard, r); copyErr != nil {
				err = copyErr
			}
			r.Close()
			return nil, util.StatusWrapf(err, "Output directory %#v", outputDirectory.Path)
		}
		r.Close()
	}
	return dk.keys, nil
}

// deriveDigest converts a digest embedded into an action result from
// the wire format to an in-memory representation. If that fails, we
// assume that some data corruption has occurred. In that case, we
// should destroy the action result.
func (dk *digestKeys) deriveDigest(blobDigest *remoteexecution.Digest) (digest.Digest, error) {
	derivedDigest, err := dk.digestFunc.NewDigestFromProto(blobDigest)
	if err != nil {
		return digest.BadDigest, util.StatusWrapWithCode(err, codes.NotFound, "Action result contained malformed digest")
	}
	return derivedDigest, err
}

// Add a digest to the list of digests that are pending to be checked
// for existence in the Content Addressable Storage.
func (dk *digestKeys) add(blobDigest *remoteexecution.Digest) error {
	if blobDigest != nil {
		derivedDigest, err := dk.deriveDigest(blobDigest)
		if err != nil {
			return err
		}
		// Never add the digest for an empty file to the CAS.
		if derivedDigest.GetSizeBytes() != 0 {
			dk.keys = append(dk.keys, spannerGCSCAS.digestToKey(derivedDigest))
		}
	}
	return nil
}

// Leader election using Spanner
//
// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

func tryLeaderElection(ctx context.Context, cl *spanner.Client, semId int64, serviceId string, timeoutSecs int) error {
	//spannerReftimeUpdateCount.Inc()
	//start := time.Now()
	log.Printf("tryLeaderElection semId %d, serviceId %s timeoutSecs %d", semId, serviceId, timeoutSecs)
	_, err := cl.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		stmt := spanner.NewStatement(`UPDATE ` + leaderTableName + ` SET ServiceID = @serviceId, ActivityTimestamp = CURRENT_TIMESTAMP()
			WHERE SemaphoreId = @semId AND
				((ServiceId != @serviceId AND ActivityTimestamp < TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @timeout SECOND)) OR
					(ServiceId = @serviceId))`)
		stmt.Params["semId"] = semId
		stmt.Params["serviceId"] = serviceId
		stmt.Params["timeout"] = timeoutSecs
		_, err := txn.Update(ctx, stmt)
		if err != nil {
			log.Printf("election update failed: %v", err)
			//spannerReftimeUpdateFailedCount.Inc()
			return err
		}
		return nil
	})
	//backendOperationsDurationSeconds.WithLabelValues(ba.storageType, BE_SPANNER, BE_TOUCH).Observe(time.Now().Sub(start).Seconds())
	return err
}

func queryLeader(ctx context.Context, cl *spanner.Client, semId int64, timeoutSecs int) (string, error) {
	log.Printf("queryLeader semId %d timeoutSecs %d", semId, timeoutSecs)
	stmt := spanner.NewStatement(`SELECT ServiceId FROM ` + leaderTableName + ` WHERE SemaphoreId = @semId AND ActivityTimestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @timeout SECOND)`)
	stmt.Params["semId"] = semId
	stmt.Params["timeout"] = timeoutSecs
	iter := cl.Single().Query(ctx, stmt)
	defer iter.Stop()
	rowCount := 0
	var serviceId string
	var err error
	var row *spanner.Row
	for {
		row, err = iter.Next()
		if err == iterator.Done {
			err = nil
			break
		}
		if err != nil {
			log.Printf("queryLeader iterator error %v", err)
			return "", err
		}
		rowCount++
		err = row.Column(0, &serviceId)
		if err != nil {
			log.Printf("queryLeader column extraction error %v", err)
			return "", err
		}
		if serviceId == "" {
			log.Printf("row %d: no serviceId found in leader table", rowCount)
		}
	}
	if rowCount == 0 {
		log.Printf("WARNING: didn't find an active leader in table")
		// Redo the query to get the ActivityTimestamp and log it
		stmt := spanner.NewStatement(`SELECT * FROM ` + leaderTableName + ` WHERE SemaphoreId = @semId`)
		stmt.Params["semId"] = semId
		iter := cl.Single().Query(ctx, stmt)
		defer iter.Stop()
		rowCount = 0
		var serviceId string  // use this scratch variable to prevent it being returned to the caller
		var activityTs time.Time
		for {
			row, err = iter.Next()
			if err == iterator.Done {
				err = nil
				break
			}
			if err != nil {
				log.Printf("queryLeader iterator error %v", err)
				break
			}
			rowCount++
			err = row.Column(1, &serviceId)
			if err != nil {
				log.Printf("ERROR: row %d, column 1 wanted ServiceId, got %v", rowCount, err)
			}
			err = row.Column(2, &activityTs)
			if err != nil {
				log.Printf("ERROR: row %d, column 2 wanted ActivityTimestamp, got %v", rowCount, err)
			}
		}
		log.Printf("rowCount = %d, found ServiceId %s, ActivityTimestamp %s", rowCount, serviceId, activityTs)
	}
	return serviceId, err
}
