<?php
function queryUnsafe() {
    $conn = new mysqli("localhost", "user", "pass", "db");
    $result = $conn->query("SELECT 1");
    return $result;
    // $conn never closed
}
?>
