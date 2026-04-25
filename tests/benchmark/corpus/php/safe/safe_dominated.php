<?php
$allowed = ['ls', 'pwd'];
$cmd = $_GET['cmd'];
if (!in_array($cmd, $allowed)) { die('denied'); }
system($cmd);
