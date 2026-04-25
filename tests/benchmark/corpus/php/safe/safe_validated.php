<?php
$allowed = ['ls', 'pwd', 'whoami'];
$cmd = $_GET['cmd'];
if (!in_array($cmd, $allowed)) { die('denied'); }
system($cmd);
