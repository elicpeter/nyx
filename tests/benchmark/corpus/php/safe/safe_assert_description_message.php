<?php
// Precision: PHP 7.2+ `assert(bool_expr, "description")` — the second
// argument is a diagnostic message thrown with AssertionError, NOT code
// that assert() evaluates.  Distilled from glpi `tests/` (atoum/PHPUnit
// suites), where this two-argument form is pervasive and previously
// fired `php.code_exec.assert_string` on the single-quoted description.
// The first-argument anchor must suppress all of these.

namespace App\Tests;

use App\Rule;

class GuardTest
{
    public function checks($a, $b, $auth, $other): void
    {
        assert($a === $b, 'values must be equal');
        assert(!$auth instanceof \CommonDBTM, 'must be a CommonGLPI, not CommonDBTM');
        assert(is_a($auth, Rule::class, true), '$auth must be a Rule subclass');
        assert(true === $auth->isActive('tester'), 'tester plugin must be active');
        assert($auth->getID() !== $other->getID(), 'auths must be different');
    }
}
