<?php

function getEnvValue(): string {
    return getenv('APP_SECRET') ?: '';
}

function sanitizeHtml(string $input): string {
    return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
}

function executeCommand(string $cmd): void {
    exec($cmd);
}

function safeFlow(): void {
    $val = getEnvValue();
    $clean = sanitizeHtml($val);
    echo $clean;
}

function unsafeFlow(): void {
    $val = getEnvValue();
    executeCommand($val);
}

safeFlow();
unsafeFlow();
