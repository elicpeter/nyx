<?php
function handleAction($action, $input) {
    switch ($action) {
        case 'eval':
            eval($input);
            break;
        case 'exec':
            system($input);
            break;
        case 'log':
            error_log($input);
            break;
        default:
            echo "Unknown action";
    }
}
?>
