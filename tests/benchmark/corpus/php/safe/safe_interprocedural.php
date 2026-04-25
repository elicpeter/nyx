<?php
function sanitize($input) {
    return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
}
$name = $_GET['name'];
echo "<h1>Hello " . sanitize($name) . "</h1>";
