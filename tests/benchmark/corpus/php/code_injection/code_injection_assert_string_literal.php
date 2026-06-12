<?php
// Recall guard for the assert() first-argument anchor.  A string FIRST
// argument is evaluated as live PHP code under PHP < 8.0 / `zend.assertions=1`.
// The non-literal second argument ($reason) keeps this off the unrelated
// all-literal-args suppression path, so the first-argument string check is
// what decides the finding — it must keep firing `php.code_exec.assert_string`.
function debug_probe($reason)
{
    assert('shell_exec("id")', $reason);
}
