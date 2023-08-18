package io.security.springsecuritypractice.controller;


import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String index(){
        return "home";
    }

    @PostMapping("/")
    public String postIndex(){
        return "home";
    }

    @GetMapping("/admin")
    public String admin(){
        return "admin";
    }

}
