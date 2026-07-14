package main

import "os"

// Precision guard: pre-declared `var (f; err)` then `f, err = os.Open(p)` —
// Go's `expression_list` LHS for a `=` (not `:=`) multi-target assignment.
// The acquired resource handle is `f` (the FIRST LHS target), NOT the trailing
// `err` return. `f` is closed via `defer f.Close()`, so no resource-leak may
// fire. Distilled from hugo internal/js/esbuild/build.go:139
// (`contentr, err = hugofs.Os.Open(...)` + `defer contentr.Close()`). Before
// the def-attribution fix the resource was bound to `err` (an error is never
// closeable), so the defer close on `f` never cleared it and a false
// resource-leak fired on `err`.
func multiAssignPredeclaredDeferClose(path string) error {
	var (
		f   *os.File
		err error
	)
	f, err = os.Open(path)
	if f != nil {
		defer f.Close()
	}
	return err
}
