// Phase 2b.3 — gated-sink dynamic activation conservatism.
//
// When `setAttribute`'s first argument (the activation arg, attribute name)
// is a dynamic value (not a string literal), the gate must fire on *all*
// positional arguments, not just the declared `payload_args = [1]`. A
// tainted activation arg is itself a vulnerability path — an attacker who
// controls the attribute name can set `onclick=...` etc.

const userInput = document.location.hash;   // tainted (Cap::all)

// Case A — both activation and payload tainted. Tests the call still fires
// when activation is dynamic (matches the PRE_RELEASE_PLAN Phase 2b.3 case).
const attrA = userInput;
const valA = userInput;
const elA = document.createElement("div");
elA.setAttribute(attrA, valA);

// Case B — only activation is tainted; payload is a clean literal. Before
// Phase 2b.3 this would miss because `payload_args = [1]` caused sink
// scanning to look only at arg 1. Now ALL_ARGS_PAYLOAD expands to arity, so
// arg 0 (the tainted attribute name) is checked too.
const attrB = userInput;
const elB = document.createElement("span");
elB.setAttribute(attrB, "static-safe-value");
