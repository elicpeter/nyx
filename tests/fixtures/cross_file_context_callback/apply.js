// Cross-file callback helper: invokes its callback argument on the data.
// When CF-2 inlines this body at the caller site, the callback arg at the
// caller (`child_process.exec`) is visible to the inline re-analysis —
// its summary's `param_to_sink` kicks in, so the taint flow from
// `process.env.USER_CMD` surfaces a finding.

function apply(fn, data) {
    return fn(data);
}

module.exports = { apply };
