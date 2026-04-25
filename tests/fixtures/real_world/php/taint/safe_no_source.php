<?php

$dir = "/var/log";
$cmd = "ls -la " . $dir;
system($cmd);
echo "Listed directory\n";
