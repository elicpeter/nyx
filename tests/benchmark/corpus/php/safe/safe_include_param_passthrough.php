<?php
// Composer-style autoloader: a closure or method takes a file path
// parameter and `include`s it.  The pattern rule is heuristic without
// taint, and over-fires here — the include target has no connection to
// user input within this function.  If a caller passes a tainted value,
// the engine's separate taint pipeline still flags it.

class ScopeIsolatedLoader {
    public static $includeFile = null;

    public static function init(): void {
        // Closure parameter pass-through (composer ClassLoader idiom).
        self::$includeFile = static function ($file) {
            include $file;
        };
    }

    // Method parameter pass-through.
    protected function requireRouteFile(string $file, string $appName): void {
        include $file;
    }

    private static function includeAppScript(string $script): void {
        if (file_exists($script)) {
            include $script;
        }
    }
}
