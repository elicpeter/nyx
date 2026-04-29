<?php
// PHP 7+ structural mitigation against object injection: explicit
// `allowed_classes` option restricts which classes the deserialiser may
// instantiate.  Three safe forms; none should fire
// `php.deser.unserialize`.
//
// See `tests/benchmark/corpus/php/safe/safe_unserialize_allowed_classes.php`
// for the per-corpus sibling.

class Demo {
    private const ALLOWED = [Foo::class, Bar::class];

    public function fromString(string $blob): mixed {
        return unserialize($blob, ['allowed_classes' => false]);
    }

    public function fromArray(string $blob): mixed {
        return unserialize($blob, ['allowed_classes' => [Foo::class, Bar::class]]);
    }

    public function fromConstant(string $blob): mixed {
        return unserialize($blob, ['allowed_classes' => self::ALLOWED]);
    }
}
