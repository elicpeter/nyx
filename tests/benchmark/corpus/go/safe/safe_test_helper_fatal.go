// go-safe-realrepo-006 — distilled from minio cmd/admin-handlers-users_test.go
// (and the identical pattern across xl-storage_test.go, erasure-healing_test.go,
// 49+34+12+11+9+7+7+5 findings on minio test files alone).
//
// `cfg-error-fallthrough` looks for `if err != nil { … }` whose body fails to
// terminate.  Test code idiomatically writes
//
//     if err != nil { c.Fatalf("...", err) }
//     postSink(...)
//
// where `c.Fatalf` (a `*testing.T` method) calls `runtime.Goexit()` and the
// `postSink` line is unreachable on the error path.  The rule classified
// this as fall-through because `Fatalf` looks like an ordinary call.  Engine
// fix: `src/cfg_analysis/error_handling.rs::call_never_returns` recognises
// `Fatal*`, `Panic*`, `FailNow`, `os.Exit`, `runtime.Goexit`, `log.Fatal*`,
// `panic`, etc. as terminators inside `terminates_on_all_paths`.

package safe

import (
	"context"
	"log"
	"os"
	"testing"
)

type clientHelper struct {
	bucket string
}

func (c *clientHelper) MakeBucket(ctx context.Context, name string) error { return nil }
func (c *clientHelper) PutObject(ctx context.Context, name string) error  { return nil }

func setupBucket(t *testing.T, c *clientHelper, ctx context.Context) {
	if err := c.MakeBucket(ctx, c.bucket); err != nil {
		t.Fatalf("bucket creat error: %v", err)
	}
	if err := c.PutObject(ctx, "obj"); err != nil {
		t.Fatal(err)
	}
}

func runWithExit(c *clientHelper, ctx context.Context) {
	if err := c.MakeBucket(ctx, c.bucket); err != nil {
		log.Fatalf("init failed: %v", err)
	}
	c.PutObject(ctx, "obj")
}

func runWithOsExit(c *clientHelper, ctx context.Context) {
	if err := c.MakeBucket(ctx, c.bucket); err != nil {
		os.Exit(1)
	}
	c.PutObject(ctx, "obj")
}

func runWithPanic(c *clientHelper, ctx context.Context) {
	if err := c.MakeBucket(ctx, c.bucket); err != nil {
		panic(err)
	}
	c.PutObject(ctx, "obj")
}
