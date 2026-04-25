<?php
function querySafe() {
    $conn = new mysqli("localhost", "user", "pass", "db");
    $result = $conn->query("SELECT 1");
    $conn->close();
    return $result;
}
?>
