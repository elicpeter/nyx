<?php
// Synthetic XXE precision guard: tainted XML reaches DOMDocument->loadXML with
// NO options argument, which is XXE-safe by default (libxml >= 2.9 rejects
// external entities unless a dangerous LIBXML_* flag is passed). Pins the
// presence-aware gate fix (CVE-2025-48882): an ABSENT ValueMatch activation
// arg must suppress the gate rather than fire conservatively.
$xml = $_POST['doc'];
$dom = new DOMDocument();
$dom->loadXML($xml);
