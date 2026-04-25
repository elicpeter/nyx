// `state-resource-leak-possible` and `state-resource-leak` previously
// fired on Go methods whose internal `c.mu.Lock()`/`defer c.mu.Unlock()`
// pattern was misclassified as proxy-acquiring the receiver `c`.
// Two engine bugs combined:
//   1. The proxy-receiver extractor took the ROOT identifier of any
//      multi-segment callee (`c.writer.header().set` → `c`).
//   2. `state-resource-leak-possible` section 2b's exception-path
//      heuristic ran on Go even though the comment scoped it to JS/TS.
//
// gin/context.go's `func (c *Context) Set(...)` is the canonical shape:
// a method whose body uses Lock/Unlock to guard mutation and whose
// receiver is NOT a resource handle.
package main

import "sync"

type Context struct {
	mu     sync.RWMutex
	Keys   map[any]any
	Errors []error
}

func (c *Context) reset() {
	c.Keys = nil
}

func (c *Context) Error(e error) error {
	c.Errors = append(c.Errors, e)
	return e
}

func (c *Context) Set(key any, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Keys == nil {
		c.Keys = make(map[any]any)
	}
	c.Keys[key] = value
}

func (c *Context) Get(key any) (value any, exists bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	value, exists = c.Keys[key]
	return
}

// Realistic call-site that mixes direct Set with chained-receiver
// helpers — the FP previously fired here too because
// `c.writer.header().set` was misattributed to `c`.
func (c *Context) Process(key, value string) {
	c.Set(key, value)
	if v, ok := c.Get(key); ok {
		_ = v
	}
}
