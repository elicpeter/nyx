<?php
function readAndLeak($path) {
    $fh = fopen($path, 'r');
    $data = fread($fh, 1024);
    return $data;
}

function readAndClose($path) {
    $fh = fopen($path, 'r');
    $data = fread($fh, 1024);
    fclose($fh);
    return $data;
}

function doubleClose($path) {
    $fh = fopen($path, 'r');
    fclose($fh);
    fclose($fh);
}
?>
