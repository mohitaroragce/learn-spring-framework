package com.boot3.springSecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloWorldResource {

	// By default password gets generated in the log, example : Using generated
	// security
	// password: 428129c9-42a9-4354-9dcb-0f0043727184

	@GetMapping("/helloWorld")
	public String helloWorld() {
		return "Hello World";
	}

}
