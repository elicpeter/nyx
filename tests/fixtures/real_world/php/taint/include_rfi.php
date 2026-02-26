<?php
$page = $_GET['page'];
include($page . '.php');

// Safe version
$allowed = ['home', 'about', 'contact'];
$safe_page = $_GET['page'];
if (in_array($safe_page, $allowed)) {
    include($safe_page . '.php');
}
?>
