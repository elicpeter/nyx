<?php
$name = $_GET['name'];
error_log("User requested: " . $name);
$len = strlen($name);
echo $len;
