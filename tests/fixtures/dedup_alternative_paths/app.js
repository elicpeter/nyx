// Regression fixture: the dedup pass must preserve both a validated
// flow and an unvalidated flow that share (body_id, sink, source)
// rather than silently keeping only the validated one.
//
// Each exec() call is a distinct CFG node (so the historic
// (body, sink, source) tuple already kept them apart), but the
// fixture additionally asserts that:
//   * both flows surface as taint findings,
//   * they differ on `path_validated`, and
//   * each finding's `finding_id` + `alternative_finding_ids` are
//     populated so downstream tooling can render them as siblings
//     when they do collide on the dedup key.

const cp = require('child_process');

function handler(req) {
    const input = process.env.USER_INPUT;
    if (isWhitelisted(req)) {
        cp.exec(input);              // validated-branch flow
    } else {
        cp.exec(input);              // unvalidated-branch flow
    }
}

function isWhitelisted(req) {
    return req.trusted === true;
}

handler({});
