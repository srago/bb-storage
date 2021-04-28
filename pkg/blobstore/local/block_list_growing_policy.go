package local

// BlockListGrowingPolicy is used by OldCurrentNewLocationBlobMap to
// determine whether the number of Blocks in the underlying BlockList is
// allowed to grow.
type BlockListGrowingPolicy interface {
	ShouldGrowNewBlocks(currentBlocks, newBlocks int) bool
	ShouldGrowCurrentBlocks(currentBlocks int) bool
}

type immutableBlockListGrowingPolicy struct {
	desiredCurrentAndNewBlocks int
}

// NewImmutableBlockListGrowingPolicy creates an BlockListGrowingPolicy
// that is suitable for data stores that hold objects that are
// immutable, such as the Content Addressable Storage (CAS).
//
// This policy permits new objects to be written to multiple Blocks,
// which is good for ensuring that data is spread out evenly. This
// amortizes the cost of refreshing these objects in the future.
//
// It also allows the number of "new" blocks to exceed the configured
// maximum in case the number of "current" blocks is low, increasing the
// spread of data even further.
func NewImmutableBlockListGrowingPolicy(currentBlocks, newBlocks int) BlockListGrowingPolicy {
	return immutableBlockListGrowingPolicy{
		desiredCurrentAndNewBlocks: currentBlocks + newBlocks,
	}
}

func (gp immutableBlockListGrowingPolicy) ShouldGrowNewBlocks(currentBlocks, newBlocks int) bool {
	return currentBlocks+newBlocks < gp.desiredCurrentAndNewBlocks
}

func (gp immutableBlockListGrowingPolicy) ShouldGrowCurrentBlocks(currentBlocks int) bool {
	return false
}
