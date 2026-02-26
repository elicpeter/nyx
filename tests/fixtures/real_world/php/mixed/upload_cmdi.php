<?php
$filename = $_FILES['file']['name'];
$tmp = $_FILES['file']['tmp_name'];
$target = '/var/www/uploads/' . $filename;
move_uploaded_file($tmp, $target);
system('chmod 644 ' . $target);  // command injection via filename!
echo "File uploaded: " . htmlspecialchars($filename);
?>
