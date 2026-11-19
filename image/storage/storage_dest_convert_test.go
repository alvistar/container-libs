//go:build !containers_image_storage_stub

package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.podman.io/storage"
	graphdriver "go.podman.io/storage/drivers"
	"go.podman.io/storage/pkg/archive"
	"go.podman.io/storage/pkg/chunked"
)

// convertTestStore is a storage.Store that records how createNewLayer builds a layer: through PutLayer (an ordinary
// layer) or through PrepareStagedLayer + ApplyStagedLayer (the layer the driver stores from a differ).
type convertTestStore struct {
	storage.Store // nil: any other method panics
	pullOptions   map[string]string
	driver        graphdriver.Driver

	putLayer     int
	prepared     int
	applied      []storage.ApplyStagedLayerOptions
	cleanedUp    int
	stagedOutput graphdriver.DriverWithDifferOutput

	layers    []storage.Layer // found by LayersByUncompressedDigest and LayersByCompressedDigest
	layerDiff []byte          // what Diff returns for them
}

func (s *convertTestStore) PullOptions() map[string]string { return s.pullOptions }

func (s *convertTestStore) GraphDriver() (graphdriver.Driver, error) { return s.driver, nil }

func (s *convertTestStore) LayersByUncompressedDigest(d digest.Digest) ([]storage.Layer, error) {
	return s.layers, nil
}

func (s *convertTestStore) LayersByCompressedDigest(d digest.Digest) ([]storage.Layer, error) {
	return s.layers, nil
}

func (s *convertTestStore) Diff(from, to string, options *storage.DiffOptions) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(s.layerDiff)), nil
}

func (s *convertTestStore) PutLayer(id, parent string, names []string, mountLabel string, writeable bool, options *storage.LayerOptions, diff io.Reader) (*storage.Layer, int64, error) {
	s.putLayer++
	return &storage.Layer{ID: id, Parent: parent}, 0, nil
}

func (s *convertTestStore) PrepareStagedLayer(options *graphdriver.ApplyDiffWithDifferOpts, differ graphdriver.Differ) (*graphdriver.DriverWithDifferOutput, error) {
	s.prepared++
	out := s.stagedOutput
	return &out, nil
}

func (s *convertTestStore) ApplyStagedLayer(args storage.ApplyStagedLayerOptions) (*storage.Layer, error) {
	s.applied = append(s.applied, args)
	return &storage.Layer{ID: args.ID, Parent: args.ParentLayer}, nil
}

func (s *convertTestStore) CleanupStagedLayer(diffOutput *graphdriver.DriverWithDifferOutput) error {
	s.cleanedUp++
	return nil
}

// A driver that stores the output of a differ (as overlay does), and one that does not (as vfs).
type differDriver struct{ graphdriver.Driver }

func (differDriver) ApplyDiffWithDiffer(*graphdriver.ApplyDiffWithDifferOpts, graphdriver.Differ) (graphdriver.DriverWithDifferOutput, error) {
	return graphdriver.DriverWithDifferOutput{}, nil
}
func (differDriver) ApplyDiffFromStagingDirectory(string, string, *graphdriver.DriverWithDifferOutput, *graphdriver.ApplyDiffWithDifferOpts) error {
	return nil
}
func (differDriver) CleanupStagingDirectory(string) error { return nil }
func (differDriver) DifferTarget(string) (string, error)  { return "", nil }

type plainDriver struct{ graphdriver.Driver }

type fakeDiffer struct{}

func (fakeDiffer) ApplyDiff(string, *archive.TarOptions, *graphdriver.DifferOptions) (graphdriver.DriverWithDifferOutput, error) {
	return graphdriver.DriverWithDifferOutput{}, nil
}
func (fakeDiffer) Close() error { return nil }

// newConvertTestDestination returns a destination whose layer blob is the cached file of blobDigest, as after a
// PutBlob of a local or reused blob, and the fake store under it.
func newConvertTestDestination(t *testing.T, pullOptions map[string]string, driver graphdriver.Driver, blobDigest digest.Digest) (*storageImageDestination, *convertTestStore) {
	store := &convertTestStore{pullOptions: pullOptions, driver: driver}
	file := filepath.Join(t.TempDir(), "layer")
	require.NoError(t, os.WriteFile(file, []byte("not a real tar, the differ is a fake"), 0o600))
	dest := &storageImageDestination{imageRef: storageReference{transport: storageTransport{store: store}}, directory: t.TempDir()}
	dest.lockProtected.filenames = map[digest.Digest]string{blobDigest: file}
	dest.lockProtected.fileSizes = map[digest.Digest]int64{}
	dest.lockProtected.blobDiffIDs = map[digest.Digest]digest.Digest{}
	return dest, store
}

func TestCreateNewLayerConvertsWithConvertImages(t *testing.T) {
	blobDigest := digest.FromString("blob")
	diffID := digest.FromString("diff")
	ctx := context.WithValue(context.Background(), struct{}{}, "the caller's context")
	var differCtx context.Context
	var differAnnotations map[string]string
	var differDigest digest.Digest
	origNewDiffer := newConvertingDiffer
	t.Cleanup(func() { newConvertingDiffer = origNewDiffer })
	newConvertingDiffer = func(ctx context.Context, store storage.Store, blobDigest digest.Digest, blobSize int64, annotations map[string]string, iss chunked.ImageSourceSeekable) (graphdriver.Differ, error) {
		differCtx, differAnnotations, differDigest = ctx, annotations, blobDigest
		return fakeDiffer{}, nil
	}
	trusted := trustedLayerIdentityData{diffID: diffID, blobDigest: blobDigest}

	// convert_images and a driver that stores differ output: the layer goes through the converting differ
	dest, store := newConvertTestDestination(t, map[string]string{"enable_partial_images": "true", "convert_images": "true"}, differDriver{}, blobDigest)
	store.stagedOutput = graphdriver.DriverWithDifferOutput{UncompressedDigest: diffID}
	layer, err := dest.createNewLayer(ctx, 0, trusted, "parent", "new")
	require.NoError(t, err)
	assert.Equal(t, "new", layer.ID)
	assert.Equal(t, 0, store.putLayer)
	assert.Equal(t, 1, store.prepared)
	require.Len(t, store.applied, 1)
	assert.Equal(t, "new", store.applied[0].ID)
	assert.Equal(t, "parent", store.applied[0].ParentLayer)
	assert.Equal(t, diffID, store.applied[0].DiffOutput.UncompressedDigest)
	assert.Same(t, ctx, differCtx, "the differ gets the caller's context")
	assert.Empty(t, differAnnotations, "no TOC: the differ converts the whole layer")
	assert.Equal(t, blobDigest, differDigest, "the differ checks the cached blob against its digest")

	// a blob reused on another parent, with no cached file: the layer is created from the uncompressed diff of the
	// existing layer, so the differ must check that diff against the DiffID, not against the (unknown) blob digest
	dest, store = newConvertTestDestination(t, map[string]string{"enable_partial_images": "true", "convert_images": "true"}, differDriver{}, digest.FromString("another blob"))
	store.layerDiff = []byte("the uncompressed diff of the existing layer")
	reusedDiffID := digest.FromBytes(store.layerDiff)
	store.layers = []storage.Layer{{ID: "existing", UncompressedDigest: reusedDiffID}}
	store.stagedOutput = graphdriver.DriverWithDifferOutput{UncompressedDigest: reusedDiffID}
	differDigest = "unset"
	layer, err = dest.createNewLayer(ctx, 0, trustedLayerIdentityData{diffID: reusedDiffID}, "other-parent", "reused")
	require.NoError(t, err)
	assert.Equal(t, "reused", layer.ID)
	assert.Equal(t, 0, store.putLayer)
	require.Len(t, store.applied, 1)
	assert.Equal(t, reusedDiffID, differDigest, "the file holds the uncompressed diff: its digest is the DiffID")

	// the same, with no DiffID known for the existing layer: the digest of the file is computed
	dest, store = newConvertTestDestination(t, map[string]string{"enable_partial_images": "true", "convert_images": "true"}, differDriver{}, digest.FromString("another blob"))
	store.layerDiff = []byte("an uncompressed diff with no recorded digest")
	store.layers = []storage.Layer{{ID: "existing"}}
	store.stagedOutput = graphdriver.DriverWithDifferOutput{UncompressedDigest: digest.FromBytes(store.layerDiff)}
	differDigest = "unset"
	_, err = dest.createNewLayer(ctx, 0, trustedLayerIdentityData{blobDigest: digest.FromString("unknown blob")}, "other-parent", "reused")
	require.NoError(t, err)
	assert.Equal(t, digest.FromBytes(store.layerDiff), differDigest)

	// the converted layer has another DiffID: refused, the staged layer cleaned up, nothing applied
	dest, store = newConvertTestDestination(t, map[string]string{"enable_partial_images": "true", "convert_images": "true"}, differDriver{}, blobDigest)
	store.stagedOutput = graphdriver.DriverWithDifferOutput{UncompressedDigest: digest.FromString("other")}
	_, err = dest.createNewLayer(ctx, 0, trusted, "parent", "new")
	require.Error(t, err)
	assert.Empty(t, store.applied)
	assert.Equal(t, 1, store.cleanedUp)

	// without convert_images, or on a driver without differ support: the ordinary layer, as before
	for _, c := range []struct {
		pullOptions map[string]string
		driver      graphdriver.Driver
	}{
		{map[string]string{"enable_partial_images": "true"}, differDriver{}},
		{map[string]string{"enable_partial_images": "true", "convert_images": "false"}, differDriver{}},
		{map[string]string{"enable_partial_images": "true", "convert_images": "true"}, plainDriver{}},
	} {
		dest, store = newConvertTestDestination(t, c.pullOptions, c.driver, blobDigest)
		_, err = dest.createNewLayer(ctx, 0, trusted, "parent", "new")
		require.NoError(t, err)
		assert.Equal(t, 1, store.putLayer, "%v %T", c.pullOptions, c.driver)
		assert.Equal(t, 0, store.prepared, "%v %T", c.pullOptions, c.driver)
	}

	// the differ cannot be used (partial images disabled): the ordinary layer, as before
	newConvertingDiffer = func(context.Context, storage.Store, digest.Digest, int64, map[string]string, chunked.ImageSourceSeekable) (graphdriver.Differ, error) {
		return nil, chunked.ErrFallbackToOrdinaryLayerDownload{Err: errors.New("partial images are disabled")}
	}
	dest, store = newConvertTestDestination(t, map[string]string{"convert_images": "true"}, differDriver{}, blobDigest)
	_, err = dest.createNewLayer(ctx, 0, trusted, "parent", "new")
	require.NoError(t, err)
	assert.Equal(t, 1, store.putLayer)
	assert.Equal(t, 0, store.prepared)
}
