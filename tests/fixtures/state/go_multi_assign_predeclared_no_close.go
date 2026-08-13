package main

import "os"

// Recall guard paired with the multi-target `=` assignment def-attribution
// fix. `f, err = os.Open(p)` (pre-declared `var (f; err)`, Go's
// `expression_list` LHS) with NO close on `f` must still fire the
// resource-leak rule ON THE HANDLE `f` — the FIRST LHS target — proving the fix
// binds the resource to the handle, not the trailing `err`, and did not
// over-suppress.
func multiAssignPredeclaredNoClose(path string) (int64, error) {
	var (
		f   *os.File
		err error
	)
	f, err = os.Open(path)
	if err != nil {
		return 0, err
	}
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}
