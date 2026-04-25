<?php
function read_and_close($path) {
    $fh = fopen($path, 'r');
    $data = fread($fh, 1024);
    fclose($fh);
    return $data;
}
