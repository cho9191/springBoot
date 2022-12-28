package com.example.demo.controller;

import org.springframework.http.ResponseCookie;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;

@RestController
public class Controller {

    @GetMapping("/index")
    public String helloController(){
        return "hellocontroller";
    }

    @GetMapping("/session")
    public void test(@AuthenticationPrincipal User user, HttpSession httpSession){

        String username = user.getUsername();

        String sessionId = httpSession.getId();

        System.out.println("username : "+username+"   sessionId : "+sessionId);

    }

    @GetMapping("/index1")
    public void index1(@AuthenticationPrincipal User user, HttpSession httpSession){

        String username = user.getUsername();

        String sessionId = httpSession.getId();

        System.out.println("username : "+username+"   sessionId : "+sessionId);

    }

    @GetMapping("/index2")
    public void index2(@AuthenticationPrincipal User user, HttpSession httpSession){

        String username = user.getUsername();

        String sessionId = httpSession.getId();

        System.out.println("username : "+username+"   sessionId : "+sessionId);

    }
}
