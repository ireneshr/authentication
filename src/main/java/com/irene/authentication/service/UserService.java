package com.irene.authentication.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.irene.authentication.controller.UserController;
import com.irene.authentication.models.UserRequest;

@Service
public class UserService {
	// The username is not case sensitive, applies for all methods
	private static final Logger LOGGER = LoggerFactory.getLogger(UserController.class);

	private final UserDetailsManager userDetailsManager;
	private final PasswordEncoder passwordEncoder;

	public UserService(@Qualifier("jdbcUserManager") UserDetailsManager userDetailsManager,
			PasswordEncoder passwordEncoder) {
		this.userDetailsManager = userDetailsManager;
		this.passwordEncoder = passwordEncoder;
	}

	public boolean checkIfUserExists(String username) {
		LOGGER.info("Checking if user '{}' exists.", username);
		return userDetailsManager.userExists(username);
	}

	public void createUser(UserRequest request) {
		LOGGER.info("Started creating user '{}'.", request.getUsername());

		if (checkIfUserExists(request.getUsername())) {
			LOGGER.error("Username '{}' exists.", request.getUsername());
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username exists.");
		}

		userDetailsManager.createUser(User.withUsername(request.getUsername())
				.password(passwordEncoder.encode(request.getPassword())).roles(request.getRole()).build());
		LOGGER.info("User created successfully for '{}'.", request.getUsername());
	}

	public void updateUser(UserRequest request) {
		LOGGER.info("Started updating user '{}'.", request.getUsername());
		if (!checkIfUserExists(request.getUsername())) {
			LOGGER.error("Username '{}' does not exist and cannot be updated.", request.getUsername());
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username does not exist.");
		}
		String dbRole = request.getRole().toUpperCase();
		userDetailsManager.updateUser(User.withUsername(request.getUsername())
				.password(passwordEncoder.encode(request.getPassword())).roles(dbRole).build());
		LOGGER.info("User updated successfully for '{}'.", request.getUsername());
	}

	public void deleteUser(String username) {
		LOGGER.info("Started deleting user '{}'.", username);
		userDetailsManager.deleteUser(username);
		LOGGER.info("User deleted successfully for '{}'.", username);
	}

}
