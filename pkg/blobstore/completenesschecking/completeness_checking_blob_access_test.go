package completenesschecking_test

import (
	"context"
	"testing"

	remoteexecution "github.com/bazelbuild/remote-apis/build/bazel/remote/execution/v2"
	"github.com/buildbarn/bb-storage/internal/mock"
	"github.com/buildbarn/bb-storage/pkg/blobstore/buffer"
	"github.com/buildbarn/bb-storage/pkg/blobstore/completenesschecking"
	"github.com/buildbarn/bb-storage/pkg/digest"
	"github.com/buildbarn/bb-storage/pkg/testutil"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCompletenessCheckingBlobAccess(t *testing.T) {
	ctrl, ctx := gomock.WithContext(context.Background(), t)

	actionCache := mock.NewMockBlobAccess(ctrl)
	contentAddressableStorage := mock.NewMockBlobAccess(ctrl)
	completenessCheckingBlobAccess := completenesschecking.NewCompletenessCheckingBlobAccess(
		actionCache,
		contentAddressableStorage,
		5,
		1000)

	actionDigest := digest.MustNewDigest("hello", "d41d8cd98f00b204e9800998ecf8427e", 123)

	t.Run("ActionCacheFailure", func(t *testing.T) {
		// Errors on the backing action cache should be passed
		// on directly.
		actionCache.EXPECT().Get(ctx, actionDigest).Return(buffer.NewBufferFromError(status.Error(codes.NotFound, "Action not found")))

		_, err := completenessCheckingBlobAccess.Get(ctx, actionDigest).ToProto(&remoteexecution.ActionResult{}, 1000)
		require.Equal(t, err, status.Error(codes.NotFound, "Action not found"))
	})

	t.Run("BadDigest", func(t *testing.T) {
		// In case the ActionResult or one of the referenced
		// Tree objects contains a malformed digest, act as if
		// the ActionResult did not exist. This should cause the
		// client to rebuild the action.
		dataIntegrityCallback := mock.NewMockDataIntegrityCallback(ctrl)
		dataIntegrityCallback.EXPECT().Call(true)
		actionCache.EXPECT().Get(ctx, actionDigest).Return(
			buffer.NewProtoBufferFromProto(
				&remoteexecution.ActionResult{
					StdoutDigest: &remoteexecution.Digest{
						Hash:      "this is a malformed hash",
						SizeBytes: 12,
					},
				},
				buffer.BackendProvided(dataIntegrityCallback.Call)))

		_, err := completenessCheckingBlobAccess.Get(ctx, actionDigest).ToProto(&remoteexecution.ActionResult{}, 1000)
		testutil.RequireEqualStatus(t, status.Error(codes.NotFound, "Action result contained malformed digest: Unknown digest hash length: 24 characters"), err)
	})

	t.Run("MissingInput", func(t *testing.T) {
		dataIntegrityCallback := mock.NewMockDataIntegrityCallback(ctrl)
		dataIntegrityCallback.EXPECT().Call(true)
		actionCache.EXPECT().Get(ctx, actionDigest).Return(
			buffer.NewProtoBufferFromProto(
				&remoteexecution.ActionResult{
					OutputFiles: []*remoteexecution.OutputFile{
						{
							Path: "bazel-out/foo.o",
							Digest: &remoteexecution.Digest{
								Hash:      "8b1a9953c4611296a827abf8c47804d7",
								SizeBytes: 5,
							},
						},
					},
					StderrDigest: &remoteexecution.Digest{
						Hash:      "6fc422233a40a75a1f028e11c3cd1140",
						SizeBytes: 7,
					},
				},
				buffer.BackendProvided(dataIntegrityCallback.Call)))
		contentAddressableStorage.EXPECT().FindMissing(
			ctx,
			digest.NewSetBuilder().
				Add(digest.MustNewDigest("hello", "8b1a9953c4611296a827abf8c47804d7", 5)).
				Add(digest.MustNewDigest("hello", "6fc422233a40a75a1f028e11c3cd1140", 7)).
				Build(),
		).Return(
			digest.MustNewDigest("hello", "8b1a9953c4611296a827abf8c47804d7", 5).ToSingletonSet(),
			nil)

		_, err := completenessCheckingBlobAccess.Get(ctx, actionDigest).ToProto(&remoteexecution.ActionResult{}, 1000)
		require.Equal(t, err, status.Error(codes.NotFound, "Object 8b1a9953c4611296a827abf8c47804d7-5-hello referenced by the action result is not present in the Content Addressable Storage"))
	})

	t.Run("FindMissingError", func(t *testing.T) {
		// FindMissing() errors should get propagated.
		dataIntegrityCallback := mock.NewMockDataIntegrityCallback(ctrl)
		dataIntegrityCallback.EXPECT().Call(true)
		actionCache.EXPECT().Get(ctx, actionDigest).Return(
			buffer.NewProtoBufferFromProto(
				&remoteexecution.ActionResult{
					StderrDigest: &remoteexecution.Digest{
						Hash:      "6fc422233a40a75a1f028e11c3cd1140",
						SizeBytes: 7,
					},
				},
				buffer.BackendProvided(dataIntegrityCallback.Call)))
		contentAddressableStorage.EXPECT().FindMissing(
			ctx,
			digest.MustNewDigest("hello", "6fc422233a40a75a1f028e11c3cd1140", 7).ToSingletonSet(),
		).Return(digest.EmptySet, status.Error(codes.Internal, "Hard disk has a case of the Mondays"))

		_, err := completenessCheckingBlobAccess.Get(ctx, actionDigest).ToProto(&remoteexecution.ActionResult{}, 1000)
		testutil.RequireEqualStatus(t, status.Error(codes.Internal, "Failed to determine existence of child objects: Hard disk has a case of the Mondays"), err)
	})

	t.Run("GetTreeError", func(t *testing.T) {
		// GetTree() errors should get propagated.
		dataIntegrityCallback := mock.NewMockDataIntegrityCallback(ctrl)
		dataIntegrityCallback.EXPECT().Call(true)
		actionCache.EXPECT().Get(ctx, actionDigest).Return(
			buffer.NewProtoBufferFromProto(
				&remoteexecution.ActionResult{
					OutputDirectories: []*remoteexecution.OutputDirectory{
						{
							Path: "bazel-out/foo",
							TreeDigest: &remoteexecution.Digest{
								Hash:      "8b1a9953c4611296a827abf8c47804d7",
								SizeBytes: 5,
							},
						},
					},
				},
				buffer.BackendProvided(dataIntegrityCallback.Call)))
		contentAddressableStorage.EXPECT().Get(
			ctx,
			digest.MustNewDigest("hello", "8b1a9953c4611296a827abf8c47804d7", 5),
		).Return(buffer.NewBufferFromError(status.Error(codes.Internal, "Hard disk has a case of the Mondays")))

		_, err := completenessCheckingBlobAccess.Get(ctx, actionDigest).ToProto(&remoteexecution.ActionResult{}, 1000)
		testutil.RequireEqualStatus(t, status.Error(codes.Internal, "Failed to fetch output directory \"bazel-out/foo\": Hard disk has a case of the Mondays"), err)
	})

	t.Run("Success", func(t *testing.T) {
		// Successful checking of existence of dependencies.
		// Below is an ActionResult that contains five
		// references to blobs, of which one is a Tree object.
		// The Tree contains two references to files. As the
		// batch size of FindMissing() is five, we should see
		// two FindMissing() calls (as ceil((5 + 2) / 5) == 2).
		actionResult := remoteexecution.ActionResult{
			OutputFiles: []*remoteexecution.OutputFile{
				{
					Path: "bazel-out/foo.o",
					Digest: &remoteexecution.Digest{
						Hash:      "38837949e2518a6e8a912ffb29942788",
						SizeBytes: 10,
					},
				},
				{
					Path: "bazel-out/foo.d",
					Digest: &remoteexecution.Digest{
						Hash:      "ebbbb099e9d2f7892d97ab3640ae8283",
						SizeBytes: 9,
					},
				},
			},
			OutputDirectories: []*remoteexecution.OutputDirectory{
				{
					Path: "bazel-out/foo",
					TreeDigest: &remoteexecution.Digest{
						Hash:      "8b1a9953c4611296a827abf8c47804d7",
						SizeBytes: 5,
					},
				},
			},
			StdoutDigest: &remoteexecution.Digest{
				Hash:      "136de6de72514772b9302d4776e5c3d2",
				SizeBytes: 4,
			},
			StderrDigest: &remoteexecution.Digest{
				Hash:      "41d7247285b686496aa91b56b4c48395",
				SizeBytes: 11,
			},
		}
		dataIntegrityCallback1 := mock.NewMockDataIntegrityCallback(ctrl)
		dataIntegrityCallback1.EXPECT().Call(true)
		actionCache.EXPECT().Get(ctx, actionDigest).Return(
			buffer.NewProtoBufferFromProto(
				&actionResult,
				buffer.BackendProvided(dataIntegrityCallback1.Call)))
		dataIntegrityCallback2 := mock.NewMockDataIntegrityCallback(ctrl)
		dataIntegrityCallback2.EXPECT().Call(true)
		contentAddressableStorage.EXPECT().Get(
			ctx,
			digest.MustNewDigest("hello", "8b1a9953c4611296a827abf8c47804d7", 5),
		).Return(buffer.NewProtoBufferFromProto(&remoteexecution.Tree{
			Root: &remoteexecution.Directory{
				// Directory digests should not be part of
				// FindMissing(), as references to directories
				// are contained within the Tree object itself.
				Directories: []*remoteexecution.DirectoryNode{
					{
						Digest: &remoteexecution.Digest{
							Hash:      "7a3435d88e819881cbe9d430a340d157",
							SizeBytes: 10,
						},
					},
				},
				Files: []*remoteexecution.FileNode{
					{
						Digest: &remoteexecution.Digest{
							Hash:      "eda14e187a768b38eda999457c9cca1e",
							SizeBytes: 6,
						},
					},
				},
			},
			Children: []*remoteexecution.Directory{
				{
					Files: []*remoteexecution.FileNode{
						{
							Digest: &remoteexecution.Digest{
								Hash:      "6c396013ff0ebff6a2a96cdc20a4ba4c",
								SizeBytes: 5,
							},
						},
					},
				},
				{},
			},
		}, buffer.BackendProvided(dataIntegrityCallback2.Call)))
		contentAddressableStorage.EXPECT().FindMissing(
			ctx,
			digest.NewSetBuilder().
				Add(digest.MustNewDigest("hello", "38837949e2518a6e8a912ffb29942788", 10)).
				Add(digest.MustNewDigest("hello", "ebbbb099e9d2f7892d97ab3640ae8283", 9)).
				Add(digest.MustNewDigest("hello", "8b1a9953c4611296a827abf8c47804d7", 5)).
				Add(digest.MustNewDigest("hello", "136de6de72514772b9302d4776e5c3d2", 4)).
				Add(digest.MustNewDigest("hello", "41d7247285b686496aa91b56b4c48395", 11)).
				Build(),
		).Return(digest.EmptySet, nil)
		contentAddressableStorage.EXPECT().FindMissing(
			ctx,
			digest.NewSetBuilder().
				Add(digest.MustNewDigest("hello", "eda14e187a768b38eda999457c9cca1e", 6)).
				Add(digest.MustNewDigest("hello", "6c396013ff0ebff6a2a96cdc20a4ba4c", 5)).
				Build(),
		).Return(digest.EmptySet, nil)

		actualResult, err := completenessCheckingBlobAccess.Get(ctx, actionDigest).ToProto(&remoteexecution.ActionResult{}, 1000)
		require.NoError(t, err)
		testutil.RequireEqualProto(t, &actionResult, actualResult)
	})
}
