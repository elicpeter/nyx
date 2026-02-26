<?php
$filename = $_FILES['upload']['name'];
$target = '/uploads/' . $filename;
move_uploaded_file($_FILES['upload']['tmp_name'], $target);
echo "Uploaded to: " . $target;

// Safe version
$safe_name = basename($_FILES['upload']['name']);
$safe_name = preg_replace('/[^a-zA-Z0-9._-]/', '', $safe_name);
$safe_target = '/uploads/' . $safe_name;
move_uploaded_file($_FILES['upload']['tmp_name'], $safe_target);
?>
