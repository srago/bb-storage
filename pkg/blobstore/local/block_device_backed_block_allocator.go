package local

import (
	"fmt"
	"io"
	"sync"

	"github.com/buildbarn/bb-storage/pkg/atomic"
	"github.com/buildbarn/bb-storage/pkg/blobstore"
	"github.com/buildbarn/bb-storage/pkg/blobstore/buffer"
	"github.com/buildbarn/bb-storage/pkg/blockdevice"
	"github.com/buildbarn/bb-storage/pkg/digest"
	pb "github.com/buildbarn/bb-storage/pkg/proto/blobstore/local"
	"github.com/prometheus/client_golang/prometheus"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

var (
	blockDeviceBackedBlockAllocatorPrometheusMetrics sync.Once

	blockDeviceBackedBlockAllocatorAllocations = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "buildbarn",
			Subsystem: "blobstore",
			Name:      "block_device_backed_block_allocator_allocations_total",
			Help:      "Number of times blocks managed by BlockDeviceBackedBlockAllocator were allocated",
		})
	blockDeviceBackedBlockAllocatorReleases = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "buildbarn",
			Subsystem: "blobstore",
			Name:      "block_device_backed_block_allocator_releases_total",
			Help:      "Number of times blocks managed by BlockDeviceBackedBlockAllocator were released",
		})

	blockDeviceBackedBlockAllocatorGetsStarted = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "buildbarn",
			Subsystem: "blobstore",
			Name:      "block_device_backed_block_allocator_gets_started_total",
			Help:      "Number of Get() operations BlockDeviceBackedBlockAllocator that were started",
		})
	blockDeviceBackedBlockAllocatorGetsCompleted = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "buildbarn",
			Subsystem: "blobstore",
			Name:      "block_device_backed_block_allocator_gets_completed_total",
			Help:      "Number of Get() operations BlockDeviceBackedBlockAllocator that were completed",
		})
)

type blockDeviceBackedBlockAllocator struct {
	blockDevice       blockdevice.BlockDevice
	readBufferFactory blobstore.ReadBufferFactory
	sectorSizeBytes   int
	blockSectorCount  int64

	lock        sync.Mutex
	freeOffsets []int64
}

// NewBlockDeviceBackedBlockAllocator implements a BlockAllocator that
// can be used by implementations of BlockList to store data. Blocks
// created by this allocator are backed by a single BlockDevice. The
// BlockDevice is partitioned into equally sized blocks that are stored
// consecutively.
//
// Blocks are initially handed out by increasing offset. Later on, the
// least recently released blocks are reused. This adds wear leveling to
// the system.
//
// This implementation also ensures that writes against underlying
// storage are all performed at sector boundaries and sizes. This
// ensures that no unnecessary reads are performed.
func NewBlockDeviceBackedBlockAllocator(blockDevice blockdevice.BlockDevice, readBufferFactory blobstore.ReadBufferFactory, sectorSizeBytes int, blockSectorCount int64, blockCount int) BlockAllocator {
	blockDeviceBackedBlockAllocatorPrometheusMetrics.Do(func() {
		prometheus.MustRegister(blockDeviceBackedBlockAllocatorAllocations)
		prometheus.MustRegister(blockDeviceBackedBlockAllocatorReleases)

		prometheus.MustRegister(blockDeviceBackedBlockAllocatorGetsStarted)
		prometheus.MustRegister(blockDeviceBackedBlockAllocatorGetsCompleted)
	})

	pa := &blockDeviceBackedBlockAllocator{
		blockDevice:       blockDevice,
		readBufferFactory: readBufferFactory,
		sectorSizeBytes:   sectorSizeBytes,
		blockSectorCount:  blockSectorCount,
	}
	for i := 0; i < blockCount; i++ {
		pa.freeOffsets = append(pa.freeOffsets, int64(i)*blockSectorCount)
	}
	return pa
}

func (pa *blockDeviceBackedBlockAllocator) toSectors(sizeBytes int64) int64 {
	// Determine the number of sectors needed to store the object.
	//
	// TODO: This can be wasteful for storing small objects with
	// large sector sizes. Should we add logic for packing small
	// objects together into a single sector?
	return (sizeBytes + int64(pa.sectorSizeBytes) - 1) / int64(pa.sectorSizeBytes)
}

func (pa *blockDeviceBackedBlockAllocator) newBlockObject(deviceOffsetSectors, writeOffsetSectors int64) Block {
	blockDeviceBackedBlockAllocatorAllocations.Inc()
	pb := &blockDeviceBackedBlock{
		blockAllocator:      pa,
		deviceOffsetSectors: deviceOffsetSectors,
		writeOffsetSectors:  writeOffsetSectors,
	}
	pb.usecount.Initialize(1)
	return pb
}

func (pa *blockDeviceBackedBlockAllocator) getBlockLocationMessage(deviceOffsetSectors int64) *pb.BlockLocation {
	return &pb.BlockLocation{
		OffsetBytes: deviceOffsetSectors * int64(pa.sectorSizeBytes),
		SizeBytes:   pa.blockSectorCount * int64(pa.sectorSizeBytes),
	}
}

func (pa *blockDeviceBackedBlockAllocator) NewBlock() (Block, *pb.BlockLocation, error) {
	pa.lock.Lock()
	defer pa.lock.Unlock()

	if len(pa.freeOffsets) == 0 {
		return nil, nil, status.Error(codes.Unavailable, "No unused blocks available")
	}
	deviceOffsetSectors := pa.freeOffsets[0]
	pa.freeOffsets = pa.freeOffsets[1:]
	return pa.newBlockObject(deviceOffsetSectors, 0), pa.getBlockLocationMessage(deviceOffsetSectors), nil
}

func (pa *blockDeviceBackedBlockAllocator) NewBlockAtLocation(location *pb.BlockLocation, writeOffsetBytes int64) (Block, bool) {
	pa.lock.Lock()
	defer pa.lock.Unlock()

	for i, deviceOffsetSectors := range pa.freeOffsets {
		if proto.Equal(pa.getBlockLocationMessage(deviceOffsetSectors), location) {
			pa.freeOffsets[i] = pa.freeOffsets[len(pa.freeOffsets)-1]
			pa.freeOffsets = pa.freeOffsets[:len(pa.freeOffsets)-1]
			return pa.newBlockObject(
				deviceOffsetSectors,
				(writeOffsetBytes+int64(pa.sectorSizeBytes)-1)/int64(pa.sectorSizeBytes),
			), true
		}
	}
	return nil, false
}

type blockDeviceBackedBlock struct {
	usecount            atomic.Int64
	blockAllocator      *blockDeviceBackedBlockAllocator
	deviceOffsetSectors int64
	writeOffsetSectors  int64
}

func (pb *blockDeviceBackedBlock) Release() {
	if c := pb.usecount.Add(-1); c < 0 {
		panic(fmt.Sprintf("Release(): Block has invalid reference count %d", c))
	} else if c == 0 {
		// Block has no remaining consumers. Allow the region in
		// storage to be reused for new data.
		pa := pb.blockAllocator
		pa.lock.Lock()
		pa.freeOffsets = append(pa.freeOffsets, pb.deviceOffsetSectors)
		pa.lock.Unlock()
		blockDeviceBackedBlockAllocatorReleases.Inc()
	}
}

func (pb *blockDeviceBackedBlock) Get(digest digest.Digest, offsetBytes, sizeBytes int64, dataIntegrityCallback buffer.DataIntegrityCallback) buffer.Buffer {
	if c := pb.usecount.Add(1); c <= 1 {
		panic(fmt.Sprintf("Get(): Block has invalid reference count %d", c))
	}
	blockDeviceBackedBlockAllocatorGetsStarted.Inc()

	return pb.blockAllocator.readBufferFactory.NewBufferFromReaderAt(
		digest,
		&blockDeviceBackedBlockReader{
			SectionReader: *io.NewSectionReader(
				pb.blockAllocator.blockDevice,
				pb.deviceOffsetSectors*int64(pb.blockAllocator.sectorSizeBytes)+offsetBytes,
				sizeBytes),
			block: pb,
		},
		sizeBytes,
		dataIntegrityCallback)
}

func (pb *blockDeviceBackedBlock) HasSpace(sizeBytes int64) bool {
	pa := pb.blockAllocator
	return pa.blockSectorCount-pb.writeOffsetSectors >= pa.toSectors(sizeBytes)
}

func (pb *blockDeviceBackedBlock) Put(sizeBytes int64) BlockPutWriter {
	if c := pb.usecount.Add(1); c <= 1 {
		panic(fmt.Sprintf("Put(): Block has invalid reference count %d", c))
	}

	writeOffsetSectors := pb.writeOffsetSectors
	pb.writeOffsetSectors += pb.blockAllocator.toSectors(sizeBytes)

	return func(b buffer.Buffer) BlockPutFinalizer {
		w := &blockDeviceBackedBlockWriter{
			w:             pb.blockAllocator.blockDevice,
			partialSector: make([]byte, 0, pb.blockAllocator.sectorSizeBytes),
			offset:        pb.deviceOffsetSectors + writeOffsetSectors,
		}

		err := b.IntoWriter(w)
		if err == nil {
			err = w.flush()
		}
		pb.Release()

		return func() (int64, error) {
			return writeOffsetSectors * int64(pb.blockAllocator.sectorSizeBytes), err
		}
	}
}

// blockDeviceBackedBlockReader reads a blob from underlying storage at
// the right offset. When released, it drops the use count on the
// containing block, so that can be freed when unreferenced.
type blockDeviceBackedBlockReader struct {
	io.SectionReader
	block *blockDeviceBackedBlock
}

func (r *blockDeviceBackedBlockReader) Close() error {
	r.block.Release()
	r.block = nil
	blockDeviceBackedBlockAllocatorGetsCompleted.Inc()
	return nil
}

// blockDeviceBackedBlockWriter writes a blob to underlying storage at
// the right offset. It could simply have used an io.SectionWriter if
// that had existed.
type blockDeviceBackedBlockWriter struct {
	w             io.WriterAt
	partialSector []byte
	offset        int64
}

func (w *blockDeviceBackedBlockWriter) Write(p []byte) (int, error) {
	sectorSizeBytes := cap(w.partialSector)

	leadingSize := 0
	if len(w.partialSector) > 0 {
		// Copy the leading part of the data into the partial
		// sector that was created previously.
		leadingSize = len(p)
		if remaining := sectorSizeBytes - len(w.partialSector); leadingSize > remaining {
			leadingSize = remaining
		}
		w.partialSector = append(w.partialSector, p[:leadingSize]...)
		if len(w.partialSector) < sectorSizeBytes {
			return leadingSize, nil
		}

		// The partial sector has become full. Write it out to
		// storage.
		if _, err := w.w.WriteAt(w.partialSector, w.offset*int64(sectorSizeBytes)); err != nil {
			return leadingSize, err
		}
		w.partialSector = w.partialSector[:0]
		w.offset++
	}

	// Write as many sectors as possible to storage directly,
	// without copying into a partial sector.
	alignedSize := (len(p) - leadingSize) / sectorSizeBytes * sectorSizeBytes
	n, err := w.w.WriteAt(p[leadingSize:leadingSize+alignedSize], w.offset*int64(sectorSizeBytes))
	writtenSectors := n / sectorSizeBytes
	w.offset += int64(writtenSectors)
	if err != nil {
		return leadingSize + writtenSectors*sectorSizeBytes, err
	}

	// Copy trailing data into a new partial sector.
	w.partialSector = append(w.partialSector, p[leadingSize+alignedSize:]...)
	return len(p), nil
}

func (w *blockDeviceBackedBlockWriter) flush() error {
	if len(w.partialSector) == 0 {
		return nil
	}

	// Add zero padding to the final sector and write it to storage.
	// Adding the padding ensures that no attempt is made to load
	// the original sector from storage.
	sectorSizeBytes := cap(w.partialSector)
	w.partialSector = append(w.partialSector, make([]byte, sectorSizeBytes-len(w.partialSector))...)
	_, err := w.w.WriteAt(w.partialSector, w.offset*int64(sectorSizeBytes))
	return err
}
