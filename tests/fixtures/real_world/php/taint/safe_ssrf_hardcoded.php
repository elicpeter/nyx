<?php
function check_health() {
    $ch = curl_init("https://api.example.com/health");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $result = curl_exec($ch);
    curl_close($ch);
    return $result;
}
