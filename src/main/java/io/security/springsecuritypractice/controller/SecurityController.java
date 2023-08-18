package io.security.springsecuritypractice.controller;


import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class SecurityController {

    @ResponseBody
    @GetMapping("/")
    public String index(){
        return "home";
    }

    @ResponseBody
    @PostMapping("/")
    public String postIndex(){
        return "home";
    }

    @GetMapping("/test")
    public String test(){
        return "test";
    }

}
