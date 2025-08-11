package com.boot3.springSecurity.controller;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ToDoController {

	private static final List<Todo> TODOs_LIST = List.of(new Todo("AWS", "Learn Aws"), new Todo("AI", "Learn AI"));

	@GetMapping("/toDos")
	public List<Todo> retrieveAllToDos() {
		return TODOs_LIST;
	}

	@GetMapping("/users/{username}/toDos")
	public Todo retrieveToDosForSpecificUser(@PathVariable String username) {
		return TODOs_LIST.get(0);
	}

	@PostMapping("/users/{username}/toDos")
	public String createToDosForSpecificUser(@PathVariable String username, @RequestBody Todo toDo) {
		return "TODO is created successfully.";
	}
}

record Todo(String username, String description) {
}
