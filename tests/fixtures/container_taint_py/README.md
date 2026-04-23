# container_taint_py — container-element taint regression

## Flow
`items.append(os.environ["INPUT"])` stores a tainted string into a
list, then `subprocess.run(items[0], shell=True)` reads it back via
subscript and sinks it.

## Current engine behaviour
The scanner **does** surface a `taint-unsanitised-flow` finding for
this fixture — container-element taint is tracked end-to-end in this
intra-procedural case.  The required expectation locks that in.

Cross-function container identity is expected to strengthen the
underlying heap-aliasing model so that cross-file variants also work
reliably.  Those cross-file variants are out of scope for this
fixture.
