<?php
function ssrf_via_typed_curl() {
    $url = $_GET['target'];
    $ch = curl_init($url);
    curl_exec($ch);
}
