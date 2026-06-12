// Synthetic regression fixture for RUSTSEC-2022-0072 (hyper-staticfile).
// Pins the chained-builder middle-gate invariant: a gated
// `header("Location", ..)` sink in the MIDDLE of a response-builder method
// chain (`new().status(..).header(..).finish()`) must still be recognised as
// an open-redirect sink. Before the fix, the chained-call rebinding descended
// to the structurally-innermost `.status(..)` and lost the gate.
use std::env;

struct Resp;
impl Resp {
    fn new() -> Self {
        Resp
    }
    fn status(self, _c: u16) -> Self {
        self
    }
    fn header(self, _n: &str, _v: String) -> Self {
        self
    }
    fn finish(self) {}
}

fn handler() {
    let next = env::var("next").unwrap();
    Resp::new().status(302).header("Location", next).finish();
}
