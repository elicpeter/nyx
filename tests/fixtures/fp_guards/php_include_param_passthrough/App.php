<?php
// Composer / PSR-4 autoloader idioms — must NOT fire
// `php.path.include_variable`.  See
// `tests/benchmark/corpus/php/safe/safe_include_param_passthrough.php`
// for the per-corpus sibling.

class ScopeIsolatedLoader {
    public static $includeFile = null;

    public static function init(): void {
        self::$includeFile = static function ($file) {
            include $file;
        };
    }

    protected function requireRouteFile(string $file, string $appName): void {
        include $file;
    }

    private static function includeAppScript(string $script): void {
        if (file_exists($script)) {
            include $script;
        }
    }
}
