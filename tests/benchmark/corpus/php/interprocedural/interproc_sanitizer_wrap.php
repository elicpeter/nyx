<?php

function clean_input($s) {
    return htmlspecialchars($s);
}

$name = $_GET['name'];
$safe = clean_input($name);
echo '<h1>' . $safe . '</h1>';
