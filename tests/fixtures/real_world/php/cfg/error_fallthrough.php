<?php
function processRequest($data) {
    $result = json_decode($data, true);
    if ($result === null) {
        error_log("Invalid JSON");
        // falls through!
    }
    system($result['command']);
}
?>
