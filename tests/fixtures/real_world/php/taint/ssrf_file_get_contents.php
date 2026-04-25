<?php
function fetch_remote() {
    $url = $_GET['url'];
    $content = file_get_contents($url);
    echo $content;
}
