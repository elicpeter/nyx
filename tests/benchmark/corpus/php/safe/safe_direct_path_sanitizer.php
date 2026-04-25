<?php
// php-safe-014: direct-return path sanitiser using `strpos` / substring checks.

function sanitize_path(string $s): string {
    if (strpos($s, '..') !== false || $s[0] === '/' || $s[0] === '\\') {
        return '';
    }
    return $s;
}

function handle(string $userPath): void {
    $safe = sanitize_path($userPath);
    file_get_contents($safe);
}
?>
