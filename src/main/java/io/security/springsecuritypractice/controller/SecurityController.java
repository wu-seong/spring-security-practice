package io.security.springsecuritypractice.controller;


import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String index(){
        return "home";
    }

    @GetMapping("/loginPage")
    public String login(){
        return "loginPage";
    }
    @GetMapping("/redirect")
    public String redirect(){
        return "redirect";
    }
}
