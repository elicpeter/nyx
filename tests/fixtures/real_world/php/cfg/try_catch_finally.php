<?php
function processFile($path) {
    $fh = fopen($path, 'r');
    try {
        $data = fread($fh, filesize($path));
        return $data;
    } catch (Exception $e) {
        echo $e->getMessage();
    } finally {
        fclose($fh);
    }
}

function leakyProcess($path) {
    $fh = fopen($path, 'r');
    $data = fread($fh, filesize($path));
    if (empty($data)) {
        return null;  // fh leaked
    }
    fclose($fh);
    return $data;
}
?>
