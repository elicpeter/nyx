<?php
$name = $_GET['name'];
error_log("User requested: " . $name);
echo "OK";
