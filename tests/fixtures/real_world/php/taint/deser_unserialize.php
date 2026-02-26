<?php
$data = $_COOKIE['session_data'];
$obj = unserialize($data);
echo $obj->name;

// Safe: JSON instead
$json_data = $_COOKIE['json_data'];
$safe_obj = json_decode($json_data);
echo $safe_obj->name;
?>
