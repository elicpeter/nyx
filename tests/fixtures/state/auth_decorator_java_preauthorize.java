package com.example;

public class UserController {
    @PreAuthorize("hasRole('ADMIN')")
    public void handle_request(Object request) {
        Runtime.getRuntime().exec("service restart");
    }
}
