<?php
$id = $_GET['id'];
$conn = new mysqli('localhost', 'root', '', 'app');
$conn->query(sprintf("SELECT * FROM users WHERE id = %s", $id));
