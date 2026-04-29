<?php
// Vulnerable counterpart to safe_include_param_passthrough.php:
// the included variable is built by concatenation inside the function
// from user-controlled input — not a parameter pass-through.  This
// must still fire `php.path.include_variable`.

function loadFromQuery(): void {
    $base = __DIR__ . '/templates/';
    $file = $base . $_GET['template'] . '.php';
    include $file;
}
