package com.oAuth.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloWorldController {

	@GetMapping("/")
	public String helloWorld(Authentication authentication) {
		System.out.println(authentication);
		return "Hello World";
	}
}
