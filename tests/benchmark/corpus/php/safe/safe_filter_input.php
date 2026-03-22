<?php
$email = filter_input(INPUT_GET, 'email', FILTER_SANITIZE_EMAIL);
echo "Your email: " . $email;
?>
