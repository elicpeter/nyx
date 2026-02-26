<?php
function conditionalClose($path, $flag) {
    $fh = fopen($path, 'r');
    if ($flag) {
        $data = fread($fh, 1024);
        fclose($fh);
        return $data;
    } else {
        return "skipped";
        // $fh leaked
    }
}
?>
