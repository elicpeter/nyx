// DATA_EXFIL fixture: a fixed destination URL and an attacker-influenced
// body.  SSRF must NOT fire (destination is hardcoded) but `Cap::DATA_EXFIL`
// must fire on the body field — request-bound bytes are leaving the process
// via the outbound request payload.
//
// Driven by `fetch_data_exfil_integration_tests.rs`.
function leakBody(req) {
    var payload = req.body.message;
    fetch('/endpoint', {
        method: 'POST',
        body: payload,
    });
}
