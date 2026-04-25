// `cfg-error-fallthrough` previously fired on functions whose ONLY
// statement is `if err != nil { log(...) }` because the rule walked
// `cfg.neighbors(if_node)` (both True and False edges) and the True
// branch's body Fprintf was treated as a "post-if sink".
//
// In gin/debug.go the canonical shape is:
//   func debugPrintError(err error) {
//       if err != nil && IsDebugging() {
//           fmt.Fprintf(DefaultErrorWriter, "[GIN-debug] %v\n", err)
//       }
//   }
// The function ends right after the if; there is no fallthrough sink.
// The rule must walk only the False edge so the body's Fprintf does
// not get counted.
package main

import "fmt"

var DefaultErrorWriter = (interface{})(nil)

func IsDebugging() bool { return false }

func debugPrintError(err error) {
	if err != nil && IsDebugging() {
		fmt.Fprintf(DefaultErrorWriter, "[GIN-debug] [ERROR] %v\n", err)
	}
}
