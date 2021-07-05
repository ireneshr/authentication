package com.irene.authentication.controller;

import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.irene.authentication.models.UserRequest;
import com.irene.authentication.roles.IsAdmin;
import com.irene.authentication.service.UserService;

@IsAdmin
@RestController
@RequestMapping("/users")
public class UserController {

	// The username is not case sensitive, applies for all methods
	private static final Logger LOGGER = LoggerFactory.getLogger(UserController.class);

	private final UserService userService;

	public UserController(UserService userService) {
		this.userService = userService;
	}

	@GetMapping("/{username}")
	public boolean checkIfUserExists(@PathVariable String username) {
		LOGGER.debug("Received request to check whether user '{}' exists or not.", username);

		return userService.checkIfUserExists(username);
	}

	@PostMapping
	public ResponseEntity<String> createUser(@Valid @RequestBody UserRequest request) {
		LOGGER.debug("Received request to create user '{}'.", request.getUsername());
		userService.createUser(request);

		return new ResponseEntity<>(HttpStatus.CREATED);
	}

	@PutMapping
	public ResponseEntity<String> updateUser(@Valid UserRequest request) {
		LOGGER.debug("Received request to update user '{}'.", request.getUsername());
		userService.updateUser(request);

		return new ResponseEntity<>(HttpStatus.NO_CONTENT);
	}

	@DeleteMapping("/{username}")
	public ResponseEntity<String> deleteUser(@PathVariable String username) {
		LOGGER.debug("Received request to delete user '{}'.", username);
		userService.deleteUser(username);

		return new ResponseEntity<>(HttpStatus.NO_CONTENT);
	}

}
