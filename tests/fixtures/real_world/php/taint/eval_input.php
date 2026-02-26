<?php
$code = $_POST['code'];
eval($code);

$expr = $_GET['expr'];
$result = eval('return ' . $expr . ';');
echo $result;
?>
