<?php
$pdo = new PDO("mysql:host=localhost;dbname=app", "user", "pass");
$name = $_GET['name'];
$result = $pdo->query("SELECT * FROM users WHERE name = '" . $name . "'");
while ($row = $result->fetch()) {
    echo $row['email'];
}
?>
