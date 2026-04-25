<?php

function build_query($filter) {
    return "SELECT * FROM logs WHERE msg LIKE '%" . $filter . "%'";
}

$filter = $_GET['filter'];
$query = build_query($filter);
mysqli_query($conn, $query);
