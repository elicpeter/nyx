<?php
function useAfterClose($url) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_close($ch);
    $response = curl_exec($ch);
    return $response;
}
?>
