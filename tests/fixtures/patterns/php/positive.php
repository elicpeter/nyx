<?php
// Positive fixture: each snippet should trigger the named pattern.

// php.code_exec.eval
function trigger_eval($code) {
    eval($code);
}

// php.code_exec.create_function
function trigger_create_function() {
    $fn = create_function('$a', 'return $a * 2;');
}

// php.code_exec.preg_replace_e
function trigger_preg_replace_e($input) {
    preg_replace('/test/e', 'strtoupper("$1")', $input);
}

// php.code_exec.assert_string
function trigger_assert($code) {
    assert("strlen('$code') > 0");
}

// php.cmdi.system
function trigger_system($cmd) {
    system($cmd);
}

// php.deser.unserialize
function trigger_unserialize($data) {
    unserialize($data);
}

// php.sqli.query_concat
function trigger_sql_concat($user) {
    mysql_query("SELECT * FROM users WHERE name = '" . $user . "'");
}

// php.path.include_variable
function trigger_include($path) {
    include $path;
}

// php.crypto.md5
function trigger_md5($data) {
    md5($data);
}

// php.crypto.sha1
function trigger_sha1($data) {
    sha1($data);
}

// php.crypto.rand
function trigger_rand() {
    $r = rand();
}
