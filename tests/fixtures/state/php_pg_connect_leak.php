<?php
function queryUnsafe() {
    $conn = pg_connect("host=localhost dbname=test");
    pg_query($conn, "SELECT 1");
    // Missing pg_close($conn)
}
