<?php
// php-safe-016: cross-function bool-returning validator with rejection.

function validate_no_dotdot(string $s): bool {
    return strpos($s, '..') === false && $s[0] !== '/' && $s[0] !== '\\';
}

function handle(string $userPath): void {
    if (!validate_no_dotdot($userPath)) {
        return;
    }
    file_get_contents($userPath);
}
?>
