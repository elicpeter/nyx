<?php
$src = $_GET['src'];
$dst = "/tmp/output.txt";
copy($src, $dst);
