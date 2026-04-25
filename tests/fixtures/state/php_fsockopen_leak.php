<?php
function connectUnsafe() {
    $sock = fsockopen("localhost", 80);
    fwrite($sock, "GET / HTTP/1.0\r\n\r\n");
    // Missing fclose($sock)
}
