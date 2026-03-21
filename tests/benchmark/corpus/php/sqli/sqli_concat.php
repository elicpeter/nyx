<?php
$id = $_GET['id'];
$conn = new mysqli('localhost', 'root', '', 'app');
$conn->query("SELECT * FROM users WHERE id = " . $id);
