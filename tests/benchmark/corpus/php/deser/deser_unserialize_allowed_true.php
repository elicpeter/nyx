<?php
// Vulnerable counterpart to safe_unserialize_allowed_classes.php:
// `allowed_classes => true` is the unsafe default — every class becomes
// constructable, which is what makes PHP unserialize a classic object
// injection sink.  This must still fire `php.deser.unserialize`.

$blob = $_POST['payload'];
$obj = unserialize($blob, ['allowed_classes' => true]);
echo $obj;
