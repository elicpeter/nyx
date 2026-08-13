// go-safe-realrepo-020 — precision guard for the multi-target `=` assignment
// resource-attribution fix.  Pre-declared `var (f; err)` then
// `f, err = os.Open(p)` (Go's `expression_list` LHS): the acquired resource
// handle is `f` (the FIRST LHS target), NOT the trailing `err` return.  `f` is
// closed via `defer f.Close()`, so no resource-leak may fire.  Distilled from
// hugo internal/js/esbuild/build.go:139 (`contentr, err = hugofs.Os.Open(...)`
// with `if contentr != nil { defer contentr.Close() }`).  Before the fix the
// resource was bound to `err` (an error is never closeable) so the defer close
// on `f` never cleared it and a false resource-leak fired on `err`.

package safe

import "os"

func multi_assign_predeclared_defer_close(path string) error {
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
