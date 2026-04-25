package com.example;

public class UserController {
    // @Override is structural — NOT auth. Finding should still fire.
    @Override
    public void handle_request(Object request) {
        Runtime.getRuntime().exec("service restart");
    }
}
