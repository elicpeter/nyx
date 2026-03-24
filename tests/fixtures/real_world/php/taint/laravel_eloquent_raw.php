<?php

function vulnerable_query($request) {
    $input = $_GET['search'];
    $result = DB::raw("SELECT * FROM users WHERE name = '" . $input . "'");
    $users = User::whereRaw("name = '" . $input . "'");
    return $users;
}
