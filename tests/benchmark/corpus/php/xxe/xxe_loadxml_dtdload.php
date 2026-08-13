<?php
// Synthetic XXE recall guard (CVE-2025-48882 family): tainted XML reaches
// DOMDocument->loadXML with the LIBXML_DTDLOAD option, which re-enables DTD /
// external-entity loading, so Nyx must fire taint-xxe.
$xml = $_POST['doc'];
$dom = new DOMDocument();
$dom->loadXML($xml, LIBXML_DTDLOAD);
