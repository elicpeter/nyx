<?php
$conn = new mysqli("localhost", "user", "pass", "db");
$id = $_GET['id'];
$result = $conn->query("SELECT * FROM users WHERE id = " . $id);
while ($row = $result->fetch_assoc()) {
    echo $row['name'];
}

// Safe version
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("s", $_GET['safe_id']);
$stmt->execute();
?>
