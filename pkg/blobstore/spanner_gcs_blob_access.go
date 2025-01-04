package blobstore

//
// BuildBarn blob access layer that stores metadata and small (<10MB) blobs in Spanner, while
// storing large blobs in a GCS bucket.  We rely on Google to delete stale action cache entries,
// but we delete CAS entries ourselves.  Update reference timestamps at insert time (in Put) and
// in FindMissing (to ensure blobs live long enough for a bazel build or test to complete).  We
// also prevent rows scheduled for deletion in Spanner from being returned by Get.
//
// To make sure action cache entries are retained on an LRU-like basis, we queue up a list of
// hashes as they are referenced and periodically update ther reference time.  Doing this one at
// a time incurs too much overhead in Spanner, so we perform bulk operations.  The downside of
// this approach is that we can lose reference updates if the servers reboot while updates are
// still queued.  Worst case, these objects will be evicted and need to be rebuilt the next time
// they are needed.  More likely, however, that these objects will be referenced before they are
// evicted.
//
// The LRU-like algorithm is intended to further reduce the frequency of object updates.  It has
// two arenas: one of objects that will expire in the configured timeframe, and one of objects
// that have been extended by having their reference times updated to the latest time they were
// referenced, but only when they have remained in the cache for half of their configured lifetimes.
// This removes the need to update young objects that are accessed multiple times when they first
// are entered into the cache.  Similarly, when an object's reference time is updated, it will
// not receive further updates until it has spent an additional amount of time in the cache equal
// to half of the configured lifetime.
//
// New design requested by Ed to remove the use of the CompletenesssCheckingBlobAccess wrapper
// around the Spanner action cache:
//
// The original one-table approach is replaced by three tables: one for maintaining the CAS, one
// for holding AC entries, and one holding associations between the two (foreign keys).  The idea
// is to rely on the foreign keys to keep all of the CAS objects for a particular action alive as
// long as the action cache entry is alive.  Since GCS object lifetimes are unaffected by Spanner
// keys, we need to manage lifetimes in GCS ourselves.  Furthermore, we can't have a row deletion
// policy for CAS objects recorded in Spanner, because Spanner doesn't allow that unless we cascade
// deletes to the Assoc table, which would remove the guarantee that as long as an action cache
// entry is valid, that all of the CAS objects it refers to are alive in the CAS.  At this point,
// it appears the proper solution is to add reference counts to CAS objects, but this becomes hard
// to deal with when you consider trying to clean up on errors.  Transactions might make that problem
// easier to deal with, but as long as we can detect that an action is not currently in progress that
// uses a given CAS blob, then we can delete the CAS blobs safely.  We use the ReferenceTime to
// detect inactive CAS blobs, because each FindMissing call updates their ReferenceTime values.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
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

	//"google.golang.org/api/iterator"
        "google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"

	"cloud.google.com/go/spanner"
	database "cloud.google.com/go/spanner/admin/database/apiv1"
	"cloud.google.com/go/storage"
	//dbpb "google.golang.org/genproto/googleapis/spanner/admin/database/v1"
	dbpb "cloud.google.com/go/spanner/admin/database/apiv1/databasepb"

	remoteexecution "github.com/bazelbuild/remote-apis/build/bazel/remote/execution/v2"
)

const (
	maxSpannerRecSz   int64 = 10*1024*1024 - 1
	maxMsgSz            int = 16 * 1024 * 1024
	maxTreeSz           int = 2 * 1024 * 1024
	acTableName             = "AC_Blobs_v1_0"
	casTableName            = "CAS_Blobs_v1_0"
	assocTableName          = "Assoc_v1_0"
	maxRefBulkSz            = 600 // Maximum number of hashes to gather before doing a bulk reftime update
	maxRefHours             = 1   // Maximum time to wait before updating reference times
	defaultDaysToLive       = 14
	nsecsPerDay              = 86400000000000

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
	spannerMalformedBlobDeletedCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "buildbarn",
			Subsystem: "blobstore",
			Name:      "spanner_malformed_blob_deleted_total",
			Help:      "Number of malformed blobs that were deleted",
		},
		[]string{"backend_type"})
	spannerMalformedBlobDeleteFailedCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "buildbarn",
			Subsystem: "blobstore",
			Name:      "spanner_malformed_blob_delete_failed_total",
			Help:      "Number of malformed blobs that could not be deleted",
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
	refChan           chan keyLoc
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

// Keep track of keys and the storage locations where they reside.
type keyLoc struct {
	key	string
	loc	int
}

// databaseName is of the form "projects/<project ID>/instances/<instance name>/databases/<database name>".
func createSpannerTables(ctx context.Context, databaseName string, daysToLive uint64) error {
	cl, err := database.NewDatabaseAdminClient(ctx)
	if err != nil {
		log.Printf("Can't create spanner database admin client: %v", err)
		return err
	}
	defer cl.Close()

	// If daysToLive is zero, use the default.
	if daysToLive == 0 {
		daysToLive = defaultDaysToLive
	}

	s := `CREATE TABLE IF NOT EXISTS ` + acTableName + ` (
		Key STRING(MAX),
		ReferenceTime TIMESTAMP NOT NULL,
                InlineData BYTES(MAX),
	) PRIMARY KEY(Key), ROW DELETION POLICY (OLDER_THAN(ReferenceTime, INTERVAL ` + strconv.FormatUint(daysToLive, 10) + ` DAY))`
	op, err := cl.UpdateDatabaseDdl(ctx, &dbpb.UpdateDatabaseDdlRequest{
		Database: databaseName,
		Statements: []string{
			s,
		},
	})
	if err != nil {
		return err
	}
	if err = op.Wait(ctx); err != nil {
		return err
	}

	s = `CREATE TABLE IF NOT EXISTS ` + casTableName + ` (
		Key STRING(MAX),
		ReferenceTime TIMESTAMP NOT NULL,
                InlineData BYTES(MAX),
	) PRIMARY KEY(Key)`
	op, err = cl.UpdateDatabaseDdl(ctx, &dbpb.UpdateDatabaseDdlRequest{
		Database: databaseName,
		Statements: []string{
			s,
		},
	})
	if err != nil {
		return err
	}
	if err = op.Wait(ctx); err != nil {
		return err
	}

	// Create the action cache table so that when an action cache entry is evicted by the delete policy, all of the matching records
	// in the Assoc table are removed.  However, we want to prevent the CAS blobs from being removed until no more action cache entries
	// refer to them, so we don't cascade deletes from the CAS table.  Attempts to delete a CAS entry will fail if any action cache
	// entries refer to it.
	s = `CREATE TABLE IF NOT EXISTS ` + assocTableName + ` (
		Key STRING(36) DEFAULT (GENERATE_UUID()),
		ActionKey STRING(MAX) NOT NULL,
		DigestKey STRING(MAX) NOT NULL,
		CONSTRAINT FKActionKey FOREIGN KEY(ActionKey) REFERENCES ` + acTableName + `(Key) ON DELETE CASCADE,
		CONSTRAINT FKDigestKey FOREIGN KEY(DigestKey) REFERENCES ` + casTableName + `(Key)
	) PRIMARY KEY(Key)`
	op, err = cl.UpdateDatabaseDdl(ctx, &dbpb.UpdateDatabaseDdlRequest{
		Database: databaseName,
		Statements: []string{
			s,
		},
	})
	if err != nil {
		return err
	}
	if err = op.Wait(ctx); err != nil {
		return err
	}

	return nil
}

func getSpannerTTL(ctx context.Context, spannerClient *spanner.Client, databaseName string, tableName string) (uint64, error) {
	stmt := spanner.NewStatement(`SELECT ROW_DELETION_POLICY_EXPRESSION FROM information_schema.tables WHERE table_name = "` + tableName + `"`)
	iter := spannerClient.Single().Query(ctx, stmt)
	row, err := iter.Next()
	iter.Stop()
	if err != nil {
		log.Printf("Can't get row deletion policy from Spanner, err = %v", err)
		return 0, err
	}
	var policy string
	err = row.Column(0, &policy)
	if err != nil {
		log.Printf("Can't get row deletion policy from Spanner, err = %v", err)
		return 0, err
	}
	log.Printf("Policy is %s", policy)
	if i := strings.Index(policy, "INTERVAL"); i != -1 {
		var days uint64
		n, err := fmt.Sscanf(policy[i:], "INTERVAL %d DAY", &days)
		if err == nil && n != 0 {
			return days, nil
		}
	}
	return 0, nil
}

func updateSpannerDeletionPolicy(ctx context.Context, databaseName string, tableName string, days uint64) error {
	cl, err := database.NewDatabaseAdminClient(ctx)
	if err != nil {
		log.Printf("Can't create spanner database admin client: %v", err)
		return err
	}
	defer cl.Close()
	s := `ALTER TABLE ` + tableName + ` REPLACE ROW DELETION POLICY (OLDER_THAN(ReferenceTime, INTERVAL ` + strconv.FormatUint(days, 10) + ` DAY))`
	op, err := cl.UpdateDatabaseDdl(ctx, &dbpb.UpdateDatabaseDdlRequest{
		Database: databaseName,
		Statements: []string{
			s,
		},
	})
	if err != nil {
		return err
	}
	if err = op.Wait(ctx); err != nil {
		return err
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
	return ((d + nsecsPerDay - 1) / nsecsPerDay) * nsecsPerDay
}

// NewSpannerGCSBlobAccess creates a BlobAccess that uses Spanner and GCS as its backing store.
func NewSpannerGCSBlobAccess(databaseName string, gcsBucketName string, readBufferFactory ReadBufferFactory, storageType string, expirationTime time.Duration, capabilitiesProvider capabilities.Provider, clientOpts []option.ClientOption) (BlobAccess, error) {
	storageType = strings.ToUpper(storageType)

	// If expirationTime is zero, use the default.  Otherwise round it up to
	// an integral number of days.
	var daysToLive uint64
	if expirationTime == 0 {
		daysToLive = defaultDaysToLive
	} else {
		daysToLive = uint64(roundUpToDay(expirationTime) / nsecsPerDay)
	}
	expirationTime = time.Duration(daysToLive * nsecsPerDay)
	// The reference time update threshold is half of the expiration age
	refUpdateThresh := expirationTime / 2
	log.Printf("daysToLive = %d, expirationTime = %d, refUpdateThresh = %d\n", daysToLive, expirationTime, refUpdateThresh)

	spannerGCSBlobAccessPrometheusMetrics.Do(func() {
		prometheus.MustRegister(spannerMalformedKeyCount)
		prometheus.MustRegister(gcsReftimeUpdateCount)
		prometheus.MustRegister(gcsReftimeUpdateFailedCount)
		prometheus.MustRegister(spannerReftimeUpdateCount)
		prometheus.MustRegister(spannerReftimeUpdateFailedCount)
		prometheus.MustRegister(spannerMalformedBlobDeletedCount)
		prometheus.MustRegister(spannerMalformedBlobDeleteFailedCount)
		prometheus.MustRegister(spannerExpiredBlobReadIgnoredCount)
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
		log.Printf("Can't create spanner client: %v", err)
		return nil, err
	}

	// If the spanner tables don't exist, create them.
	if err = createSpannerTables(ctx, databaseName, daysToLive); err != nil {
		spannerClient.Close()
		log.Printf("Can't create spanner table: %v", err)
		return nil, err
	} else if storageType == "AC" {
		// Check if we need to update the TTL.
		days, err := getSpannerTTL(ctx, spannerClient, databaseName, acTableName)
		if err != nil {
			log.Printf("Can't determine Spanner TTL: %v", err)
		}
		if days != daysToLive {
			err = updateSpannerDeletionPolicy(ctx, databaseName, acTableName, daysToLive)
			if err != nil {
				log.Printf("Can't update Spanner TTL: %v", err)
			} else {
				log.Printf("Spanner TTL changed from %d to %d days", days, daysToLive)
			}
		}
	}

	storageClient, err := storage.NewClient(ctx, clientOpts...)
	if err != nil {
		spannerClient.Close()
		log.Printf("Can't create GCS client: %v", err)
		return nil, err
	}
	gcsBucket := storageClient.Bucket(gcsBucketName)

	// If the GCS bucket doesn't exist, create it.
	_, err = gcsBucket.Attrs(ctx)
	if err == storage.ErrBucketNotExist {
		err = createGCSBucket(ctx, gcsBucket, databaseName, daysToLive)
		if err != nil {
			// We could have raced with another pod.  Check if the bucket exists.
			_, xerr := gcsBucket.Attrs(ctx)
			if xerr == storage.ErrBucketNotExist {
				// Bucket still doesn't exist.
				spannerClient.Close()
				storageClient.Close()
				log.Printf("Can't create GCS bucket: %v", err)
				return nil, err
			}
		}
	} else if err != nil {
		spannerClient.Close()
		storageClient.Close()
		log.Printf("Can't access GCS bucket: %v", err)
		return nil, err
	}

	log.Printf("NewSpannerGCSBlobAccess type %s", storageType)

	// FindMissing takes care of updaing the reference time on CAS objects, but we'd like to update
	// AC objects when they're read, to simulate an LRU cache.  Doing this one at a time is inefficient,
	// and the poor performance was noticed by users.
	var refCh chan keyLoc
	if storageType == "AC" {
		refCh = make(chan keyLoc, maxRefBulkSz)
	}

	ba := &spannerGCSBlobAccess{
		Provider:      capabilitiesProvider,
		spannerClient: spannerClient,
		gcsBucket:     gcsBucket,

		readBufferFactory: readBufferFactory,
		databaseName:      databaseName,
		storageType:       storageType,
		daysToLive:        daysToLive,
		expirationAge:     expirationTime,
		refUpdateThresh:   refUpdateThresh,
		refChan:           refCh,
	}
	if refCh != nil {
		go ba.bulkUpdate(refCh)
	}
	if storageType == "CAS" {
		spannerGCSCAS = ba
		id := os.Getenv("HOSTNAME")
		s := strings.Split(id, "-")
		// The first worker gets to handle evictions.
		if len(s) > 1 && s[0] == "worker" && s[len(s)-1] == "0" {
			go ba.periodicEvicter(ctx)
		}
	}
	return ba, nil
}

func (ba *spannerGCSBlobAccess) delete(ctx context.Context, tableName string, key string, loc int) error {
	deleteMut := spanner.Delete(tableName, spanner.Key{key})
	start := time.Now()
	_, err := ba.spannerClient.Apply(ctx, []*spanner.Mutation{deleteMut})
	backendOperationsDurationSeconds.WithLabelValues(ba.storageType, BE_SPANNER, BE_DEL).Observe(time.Now().Sub(start).Seconds())
	if err != nil {
		return err
	}

	// Now if it was also in GCS, delete it there
	if (loc & LOC_GCS) != 0 {
		object := ba.gcsBucket.Object(key)
		start := time.Now()
		err = object.Delete(ctx)
		backendOperationsDurationSeconds.WithLabelValues(ba.storageType, BE_GCS, BE_DEL).Observe(time.Now().Sub(start).Seconds())
		return err
	}

	return nil
}

func (ba *spannerGCSBlobAccess) Get(ctx context.Context, digest digest.Digest) buffer.Buffer {
	//log.Printf("SpannerGCSBlobAccess type %#+v GET digest %s", ba.storageType, digest)
	if err := util.StatusFromContext(ctx); err != nil {
		return buffer.NewBufferFromError(err)
	}
	key := ba.digestToKey(digest)
	//log.Printf("SpannerGCSBlobAccess GET key is %s", key)

	var tableName string
	if ba.storageType == "AC" {
		tableName = acTableName
	} else {
		tableName = casTableName
	}

	// Grab the row itself
	now := time.Now().UTC()
	row, err := ba.spannerClient.Single().ReadRow(ctx, tableName, spanner.Key{key}, []string{"ReferenceTime", "InlineData"})
	backendOperationsDurationSeconds.WithLabelValues(ba.storageType, BE_SPANNER, BE_GET).Observe(time.Now().Sub(now).Seconds())
	if err != nil {
		log.Printf("GET error: ReadRow key %s failed: %v", key, err)
		return buffer.NewBufferFromError(err)
	}

	var s struct {
		ReferenceTime time.Time
		InlineData    []byte
	}
	err = row.ToStruct(&s)
	if err != nil {
		log.Printf("GET error: ToStruct key %s failed: %v", key, err)
		return buffer.NewBufferFromError(err)
	}

	var loc int
	if len(s.InlineData) == 0 {
		loc |= LOC_GCS
	} else {
		loc |= LOC_SPANNER
	}

	// Exclude expired blobs -- they don't exist anymore; we're waiting for the storage to delete them.
	if !now.Before(s.ReferenceTime.Add(ba.expirationAge)) {
		spannerExpiredBlobReadIgnoredCount.Inc()
		log.Printf("Ignoring stale key %s", key)
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
			if err := ba.delete(ctx, tableName, key, loc); err == nil {
				spannerMalformedBlobDeletedCount.WithLabelValues(beType).Inc()
				log.Printf("Blob %s was malformed and has been deleted from Spanner/GCS successfully", digest.String())
			} else {
				spannerMalformedBlobDeleteFailedCount.WithLabelValues(beType).Inc()
				log.Printf("Blob %s was malformed and could not be deleted from Spanner/GCS: %v", digest.String(), err)
			}
		}
	}

	var b buffer.Buffer
	if (loc & LOC_GCS) != 0 {
		// We gotta go get it from GCS
		obj := ba.gcsBucket.Object(key)

		r, err := obj.NewReader(ctx)
		if err != nil {
			// If we couldn't read the bucket, then let's delete it from spanner (and from gcs if we can!)
			if err2 := ba.delete(ctx, tableName, key, loc); err2 == nil {
				gcsFailedReadDeletedBlobCount.Inc()
				log.Printf("Blob %s was inaccessible in GCS (due to %v) and has been deleted from Spanner/GCS successfully", digest.String(), err)
			} else {
				gcsFailedReadDeleteBlobFailedCount.Inc()
				log.Printf("Blob %s was inaccessible in GCS (due to %v) and could not be deleted from Spanner/GCS: %s", digest.String(), err, err2)
			}
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
		log.Printf("GET ERROR: key %s, type %v: %v", key, ba.storageType, err)
	}
	if ba.refChan != nil && now.After(s.ReferenceTime.Add(ba.refUpdateThresh)) {
		log.Printf("GET: scheduling touch reftime for key %s reftime %s", key, s.ReferenceTime)
		ba.refChan <- keyLoc{key: key, loc: loc}
	}
	return b
}

func (ba *spannerGCSBlobAccess) Put(ctx context.Context, digest digest.Digest, b buffer.Buffer) error {
	//log.Printf("SpannerGCSBlobAccess type %#+v PUT digest %s", ba.storageType, digest)
	if err := util.StatusFromContext(ctx); err != nil {
		b.Discard()
		return err
	}

	// If we're bigger than 10MB, we have to offload to GCS
	size, err := b.GetSizeBytes()
	if err != nil {
		log.Printf("Put Blob %s: can't get size: %v", digest, err)
		b.Discard()
		return err
	}

	key := ba.digestToKey(digest)
	//log.Printf("SpannerGCSBlobAccess PUT key is %s, size %d", key, size)

	var digestKeys []string
	if ba.storageType == "AC" {
		// Calculate list of hashes in merkle tree so we can add them to the Assoc table
		b1, b2 := b.CloneCopy(maxMsgSz)
		actionResult, err := b1.ToProto(&remoteexecution.ActionResult{}, maxMsgSz)
		if err != nil {
			b2.Discard()
			return err
		}

		digestKeys, err = ba.getDigestKeysFromActionResult(ctx, digest.GetDigestFunction(), actionResult.(*remoteexecution.ActionResult))
		if err != nil {
			b2.Discard()
			return err
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
				log.Printf("Blob %s can't be copied to GCS, close failed: %v", digest, err)
			}
		} else {
			log.Printf("Blob %s can't be copied to GCS, write failed: %v", digest, err)
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
			log.Printf("Blob %s can't be copied to Spanner: %v", digest, err)
			return err
		}
		if len(inlineData) == 0 {
			log.Printf("WARNING: ByteSlice size is 0, expected %d, key %s", size, key)
		}
	}

	// Now insert into the spanners no matter what!
	rec := spannerRecord{
		Key:           key,
		ReferenceTime: now,
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
		log.Printf("Can't create mutation for Blob %s: %v", digest, err)
		return err
	}

	start := time.Now()
	_, err = ba.spannerClient.Apply(ctx, []*spanner.Mutation{insertMut})
	backendOperationsDurationSeconds.WithLabelValues(ba.storageType, BE_SPANNER, BE_PUT).Observe(time.Now().Sub(start).Seconds())
	if err != nil {
		log.Printf("Can't apply create mutation for Blob %s: %v", digest, err)
		return err
	}

	if ba.storageType == "AC" {
		// If this is an overwrite, remove any entries for this AC entry from the Assoc table
		// TODO(ragost): try to avoid this if this is an overwrite
		ba.deleteAssociationsFromSpanner(ctx, key)
		// Add new entries to the Assoc table
		if digestKeys != nil {
			ba.addAssociationsToSpanner(ctx, key, digestKeys)
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
		//log.Printf("FINDMISSING digest %s key %s", digest, k)
		keyToDigest[k] = digest
		ksl = append(ksl, k)
	}

	// We want to grab anything not in the Blobs table.  First find what's there so we can exclude them from the list
	// of missing blobs.  Then decide which of the existing ones need their reftime to be updated.
	stmt := spanner.NewStatement(`SELECT Key, ReferenceTime FROM ` + casTableName + ` where Key IN UNNEST(@keys) and TIMESTAMP_DIFF(CURRENT_TIMESTAMP(), ReferenceTime, DAY) < @expdays`)
	stmt.Params["keys"] = ksl
	stmt.Params["expdays"] = int64(ba.daysToLive)
	start := time.Now()
	iter := ba.spannerClient.Single().Query(ctx, stmt)
	backendOperationsDurationSeconds.WithLabelValues("CAS", BE_SPANNER, BE_FM).Observe(time.Now().Sub(start).Seconds())

	missing := digest.NewSetBuilder()
	keyToRefTime := make(map[string]time.Time, digests.Length())
	err := iter.Do(func(row *spanner.Row) error {
		// Errors in this function (interpretting the row results) should only occur if someone changes the
		// schema without updating this file.
		var key string
		var refTime time.Time
		err := row.Column(0, &key)
		if err != nil {
			log.Printf("ERROR Column 0 wanted Key, got %v", err)
		}
		if key == "" {
			return nil
		}
		err = row.Column(1, &refTime)
		if err != nil {
			log.Printf("ERROR Column 1 wanted ReferenceTime, got %v", err)
		}
		//log.Printf("FOUND key %s, digest %s", key, keyToDigest[key])
		keyToRefTime[key] = refTime
		delete(keyToDigest, key)
		return nil
	})

	if err != nil {
		return digest.EmptySet, err
	}

	// Now keyToDigest consists only of missing blobs.  Prepare the missing digest set to return to the caller.
	for _, digest := range keyToDigest {
		missing.Add(digest)
	}

	// Now update the ReferenceTime field for the Spanner blobs we have.  GCS blobs also have records in spanner to make FindMissing
	// efficient and prevent large CAS blobs from being evicted before and action cache entries that reference them.
	now := time.Now().UTC()
	keys := make([]string, 0, digests.Length())
	for key, refTime := range keyToRefTime {
		if now.After(refTime.Add(ba.refUpdateThresh)) {
			log.Printf("FINDMISSING: scheduling touch reftime for key %s reftime %s", key, refTime)
			keys = append(keys, key)
		}
	}
	if len(keys) != 0 {
		ba.touchSpannerObjects(context.Background(), casTableName, keys, now)
	}

	return missing.Build(), nil
}

func (ba *spannerGCSBlobAccess) GetFromComposite(ctx context.Context, parentDigest, childDigest digest.Digest, slicer slicing.BlobSlicer) buffer.Buffer {
	b, _ := slicer.Slice(ba.Get(ctx, parentDigest), childDigest)
	return b
}

// Update the ReferenceTime field the Spanner blob.
func (ba *spannerGCSBlobAccess) touchSpannerObjects(ctx context.Context, tableName string, keys []string, t time.Time) error {
	spannerReftimeUpdateCount.Inc()
	start := time.Now()
	_, err := ba.spannerClient.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		// Hopefully this is more efficient than doing a read-modify-write.  Tried InsertOrUpdateStruct(),
		// but that set the InlineData field to NULL, contradicting the manual page that "Any column values
		// not explicitly written are preserved."
		refTime := t.Format(time.RFC3339)
		stmt := spanner.NewStatement(`UPDATE ` + tableName + ` SET ReferenceTime = TIMESTAMP(@reftime) WHERE Key in unnest(@keys)`)
		stmt.Params["keys"] = keys
		stmt.Params["reftime"] = refTime
		_, err := txn.Update(ctx, stmt)
		if err != nil {
			spannerReftimeUpdateFailedCount.Inc()
			log.Printf("Can't update reftime in %d Blobs: %v", len(keys), err)
			return err
		}
		return nil
	})
	backendOperationsDurationSeconds.WithLabelValues(ba.storageType, BE_SPANNER, BE_TOUCH).Observe(time.Now().Sub(start).Seconds())
	return err
}

func (ba *spannerGCSBlobAccess) deleteAssociationsFromSpanner(ctx context.Context, key string) error {
	// TODO(ragost): add metrics similar to spannerReftimeUpdateCount.Inc()
	// start := time.Now()
	_, err := ba.spannerClient.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		stmt := spanner.NewStatement(`DELETE FROM ` + assocTableName + ` WHERE ActionKey = @key`)
		stmt.Params["key"] = key
		_, err := txn.Update(ctx, stmt)
		if err != nil {
			// spannerReftimeUpdateFailedCount.Inc()
			log.Printf("Can't remove associations for AC key %s: %v", key, err)
			return err
		}
		return nil
	})
	// backendOperationsDurationSeconds.WithLabelValues(ba.storageType, BE_SPANNER, BE_TOUCH).Observe(time.Now().Sub(start).Seconds())
	return err
}

func (ba *spannerGCSBlobAccess) addAssociationsToSpanner(ctx context.Context, key string, digestKeys []string) error {
	// TODO(ragost): add metrics similar to spannerReftimeUpdateCount.Inc()
	var assocRecs []assocRecord
	assocRecs = make([]assocRecord, len(digestKeys))
	for idx, _ := range digestKeys {
		log.Printf("action key %s CAS key %s", key, digestKeys[idx])
		assocRecs[idx].ActionKey = key
		assocRecs[idx].DigestKey = digestKeys[idx]
	}
	// start := time.Now()
	_, err := ba.spannerClient.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
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
	// backendOperationsDurationSeconds.WithLabelValues(ba.storageType, BE_SPANNER, BE_TOUCH).Observe(time.Now().Sub(start).Seconds())
	return err
}

// Process deferred access time updates from action cache GET operations.
func (ba *spannerGCSBlobAccess) bulkUpdate(in <-chan keyLoc) {
	keys := make([]string, 0, maxRefBulkSz)
	locs := make([]int, 0, maxRefBulkSz)
	keyMap := make(map[string]bool, maxRefBulkSz) // used to dedup the list of keys
	t := time.NewTimer(maxRefHours * time.Hour)
	timedout := false
	for {
		select {
		case kl := <-in:
			if keyMap[kl.key] {
				log.Printf("SKIPPING duplicate key %s", kl.key)
			} else {
				keyMap[kl.key] = true
				keys = append(keys, kl.key)
				locs = append(locs, kl.loc)
			}
		case <-t.C:
			timedout = true
		}
		if (timedout && len(keys) != 0) || (len(keys) == maxRefBulkSz) {
			log.Printf("Processing %d delayed reftime updates", len(keys))
			timedout = true // just so we know to reset the timer if we're here because we've reached maxRefBulkSz
			now := time.Now().UTC()
			go ba.touchSpannerObjects(context.Background(), acTableName, keys, now)
			keys = make([]string, 0, maxRefBulkSz)
			locs = make([]int, 0, maxRefBulkSz)
			keyMap = make(map[string]bool, maxRefBulkSz)
		}

		// We need to reset the timer if we timed out or if we processed a bulk transfer.  We could have timed
		// out without any work to do, so always check if timedout is true here so we can reset the timer.
		// Stay away from this pattern:
		//    if !t.Stop() {
		//        <-t.C
		//    }
		//    t.Reset(...)
		// It was racy and we'd sometimes block reading from the channel.
		if timedout {
			timedout = false
			t.Stop()
			t = time.NewTimer(maxRefHours * time.Hour)
		}
	}
}

func (ba *spannerGCSBlobAccess) periodicEvicter(ctx context.Context) {
	log.Printf("I am the Evicter")
	//t := time.NewTimer(1 * time.Hour)
	t := time.NewTimer(20 * time.Minute) // only for testing
	for {
		select {
		case <-t.C:
		}

		ba.evictStaleBlobs(ctx)

		t.Stop()
		t = time.NewTimer(24 * time.Hour)
	}
}

func (ba *spannerGCSBlobAccess) evictStaleBlobs(ctx context.Context) {
	// We want to find all stale entries in the CAS and then delete them.  Start with the small blobs.
	// Paritition this into reasonable sized chunks.
	var wg sync.WaitGroup
	var mu sync.Mutex

	log.Printf("Starting Evictions...")
	count := 0
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(start int) {
			defer wg.Done()
			log.Printf("start evicting range %d to %d", start, start+15) // TODO(ragost): just for testing
			cfg := spanner.ClientConfig {
				DisableNativeMetrics: true,
			}
			cl, err := spanner.NewClientWithConfig(ctx, ba.databaseName, cfg)
			if err != nil {
				log.Printf("Can't create a spanner client: %v", err)
				return
			}
			defer cl.Close()
			for j := start; j < start + 16; j++ {
				prefix := fmt.Sprintf("'%2.2x%%'", j)
				start := time.Now()
				stmt := spanner.NewStatement(`DELETE FROM ` + casTableName +
					` WHERE InlineData IS NOT NULL AND Key LIKE @prefix AND TIMESTAMP_DIFF(CURRENT_TIMESTAMP(), ReferenceTime, DAY) >= @expdays`)
				stmt.Params["expdays"] = int64(ba.daysToLive)
				stmt.Params["prefix"] = prefix
				nrows, err := cl.PartitionedUpdate(ctx, stmt)
				if err != nil {
					// spannerReftimeUpdateFailedCount.Inc()
					log.Printf("Problems evicting small Blobs: %v", err)
					break
				} else {
					mu.Lock()
					count += int(nrows)
					mu.Unlock()
				}
				backendOperationsDurationSeconds.WithLabelValues(ba.storageType, BE_SPANNER, BE_DEL).Observe(time.Now().Sub(start).Seconds())
			}
		}(16 * i)
	}
	wg.Wait()
	log.Printf("Evicted %d small blobs from the CAS", count)


	// Now delete the stale large Blobs.  First we need to get a list of the keys so we can delete them from GCS.
	// NB: there are far fewer large Blobs than small ones, so nothing too fancy here.
	stmt := spanner.NewStatement(`SELECT Key FROM ` + casTableName + ` WHERE InlineData IS NULL AND TIMESTAMP_DIFF(CURRENT_TIMESTAMP(), ReferenceTime, DAY) >= @expdays`)
	stmt.Params["expdays"] = int64(ba.daysToLive)
	start := time.Now()
	iter := ba.spannerClient.Single().Query(ctx, stmt)

	keys := make([]string, 0, 1000)
	err := iter.Do(func(row *spanner.Row) error {
		// Errors in this function (interpretting the row results) should only occur if someone changes the
		// schema without updating this file.
		var key string
		err := row.Column(0, &key)
		if err != nil {
			log.Printf("ERROR Column 0 wanted Key, got %v", err)
		}
		if key == "" {
			return nil
		}
		keys = append(keys, key)
		return nil
	})
	backendOperationsDurationSeconds.WithLabelValues(ba.storageType, BE_SPANNER, BE_DEL).Observe(time.Now().Sub(start).Seconds())

	if err != nil {
		log.Printf("Can't evict large Blobs: %v", err)
	}

	// TODO(ragost): this needs to be in the previous transactions to avoid racing with FindMissing
	stmt = spanner.NewStatement(`DELETE FROM ` + casTableName +
		` WHERE Key IN UNNEST(@keys) AND TIMESTAMP_DIFF(CURRENT_TIMESTAMP(), ReferenceTime, DAY) >= @expdays`)
	stmt.Params["keys"] = keys
	stmt.Params["expdays"] = int64(ba.daysToLive)
	_, err = ba.spannerClient.PartitionedUpdate(ctx, stmt)
	backendOperationsDurationSeconds.WithLabelValues(ba.storageType, BE_SPANNER, BE_DEL).Observe(time.Now().Sub(start).Seconds())
	if err != nil {
		// spannerReftimeUpdateFailedCount.Inc()
		log.Printf("Problem evicting large Blobs: %v", err)
		return
	}

	// Finally remove the large blobs from GCS.
	for _, key := range keys {
		object := ba.gcsBucket.Object(key)
		start := time.Now()
		err = object.Delete(ctx)
		backendOperationsDurationSeconds.WithLabelValues(ba.storageType, BE_GCS, BE_DEL).Observe(time.Now().Sub(start).Seconds())
		if err != nil {
			log.Printf("Can't expire large Blob %s: %v", key, err)
		}
	}
	log.Printf("Evicted %d large blobs from the CAS", len(keys))
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
		dk.keys = append(dk.keys, spannerGCSCAS.digestToKey(derivedDigest))
	}
	return nil
}
