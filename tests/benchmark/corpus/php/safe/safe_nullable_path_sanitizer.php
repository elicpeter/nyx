<?php
// php-safe-015: nullable-returning sanitiser (?string) with null failure sentinel.

function sanitize_path(string $s): ?string {
    if (strpos($s, '..') !== false || $s[0] === '/' || $s[0] === '\\') {
        return null;
    }
    return $s;
}

function handle(string $userPath): void {
    $safe = sanitize_path($userPath);
    if ($safe === null) {
        return;
    }
    file_get_contents($safe);
}
?>
