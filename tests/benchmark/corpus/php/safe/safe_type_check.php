<?php
$id = $_GET['id'];
if (!is_numeric($id)) { die('bad input'); }
$conn = new mysqli('localhost', 'root', '', 'app');
$conn->query("SELECT * FROM users WHERE id = " . $id);
