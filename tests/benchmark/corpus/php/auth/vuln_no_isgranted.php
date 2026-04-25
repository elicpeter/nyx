<?php
// php-isgranted-vuln-001: top-level PHP request handler without an auth
// guard reads a user-supplied path directly into a FILE_IO sink.
// `taint-unsanitised-flow` should fire — the missing auth attribute
// leaves the privileged sink exposed to any unauthenticated caller.
$name = $_GET['file'];
echo file_get_contents("/var/data/" . $name);
