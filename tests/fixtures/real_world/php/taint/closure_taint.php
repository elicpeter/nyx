<?php
$input = $_GET['name'];
$render = function($data) {
    echo $data;
};
// Outer scope: taint flows directly to sink
echo $input;
