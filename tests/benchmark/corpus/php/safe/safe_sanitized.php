<?php
$name = $_GET['name'];
$safe = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
echo "<h1>Hello " . $safe . "</h1>";
