<?php

$cmd = $_GET['cmd'];
$safe = escapeshellarg($cmd);
system("ls " . $safe);
