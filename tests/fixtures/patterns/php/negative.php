<?php
// Negative fixture: none of these should trigger security patterns.

function safe_query($pdo, $user) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE name = ?");
    $stmt->execute([$user]);
}

function safe_hash($data) {
    return hash("sha256", $data);
}

function safe_random() {
    return random_int(1, 100);
}

function safe_include() {
    include "config.php";
}

function safe_string_ops() {
    $x = "hello";
    $y = strtoupper($x);
    $z = strlen($y);
}
