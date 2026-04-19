<?php

class UserController {
    #[IsGranted('ROLE_ADMIN')]
    public function handle_request($request) {
        exec("service restart");
    }
}
