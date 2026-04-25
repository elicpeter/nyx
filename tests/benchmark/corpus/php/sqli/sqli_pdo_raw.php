<?php
$id = $_GET['id'];
$db = new PDO('sqlite:test.db');
// Vulnerable: raw SQL string concatenation
$result = $db->query("SELECT * FROM users WHERE id = '" . $id . "'");
echo $result->fetch()['name'];
?>
