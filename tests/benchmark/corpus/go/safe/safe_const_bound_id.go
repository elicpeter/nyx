// `<lang>.auth.missing_ownership_check` previously fired on
// constant-bound `id` locals in test code:
//   id := "id"
//   value := "1"
//   c.AddParam(id, value)  // FP: `id` matches is_id_like, no
//                          //  actor-context exemption, so the
//                          //  rule fired.
// The fix tracks variables bound to literal constants (string,
// numeric, boolean) on `let` / `:=` / `var` / `const` declarations
// and excludes them from `is_relevant_target_subject`.
//
// Source: gin/context_test.go:TestContextAddParam
package main

type Context struct{ Params Params }
type Params struct{}

func (c *Context) AddParam(k, v string)        {}
func (p Params) Get(k string) (string, bool)   { return "", false }

func TestContextAddParam_likeShape() {
	c := &Context{}
	id := "id"
	value := "1"
	c.AddParam(id, value)

	if v, ok := c.Params.Get(id); ok {
		_ = v
	}
}
