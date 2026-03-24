<?php
function read_and_leak($path) {
    $fh = fopen($path, 'r');
    $data = fread($fh, 1024);
    return $data;
}
