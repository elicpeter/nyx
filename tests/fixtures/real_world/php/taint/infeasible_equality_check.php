<?php
$action = $_GET['action'];
if ($action === "safe") {
    if ($action === "dangerous") {
        // Infeasible: $action === "safe" AND $action === "dangerous"
        system($action);
    }
}
system($action);
?>
