<?php
// Safe: simplexml_load_string with NO options argument is XXE-safe by default
// (libxml >= 2.9 rejects external entities unless a dangerous LIBXML_* flag is
// passed). Regression guard for the presence-aware gate fix (CVE-2025-48882):
// an ABSENT ValueMatch activation argument must suppress the XXE gate rather
// than fire conservatively on the dynamic-unknown path.
$xml = $_GET['xml'];
$doc = simplexml_load_string($xml);
