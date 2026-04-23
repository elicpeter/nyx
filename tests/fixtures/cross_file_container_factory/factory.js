// Phase 11 cross-file container factory: a fresh container is allocated
// inside `makeBag()` and returned to the caller.  `fillBag()` mutates
// that container through its first argument and returns the same
// container.  Together they exercise the PointsToSummary.returns_fresh_alloc
// channel (factory synthesises a fresh HeapObjectId at the call site)
// plus the existing `Param(0) → Return` alias edge.

function makeBag() {
    return [];
}

function fillBag(bag, val) {
    bag.push(val);
    return bag;
}

module.exports = { makeBag, fillBag };
