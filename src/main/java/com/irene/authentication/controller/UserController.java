package com.irene.authentication.controller;

import com.irene.authentication.models.UserRequest;
import com.irene.authentication.roles.IsAdmin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@IsAdmin
@RestController
@RequestMapping("/users")
public class UserController {

    //The username is not case sensitive, applies for all methods
    private static final Logger LOGGER = LoggerFactory.getLogger(UserController.class);

    private final UserDetailsManager userDetailsManager;
    private final PasswordEncoder passwordEncoder;

    public UserController(@Qualifier("jdbcUserManager")UserDetailsManager userDetailsManager, PasswordEncoder passwordEncoder) {
        this.userDetailsManager = userDetailsManager;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/{username}")
    public boolean checkIfUserExists(@PathVariable String username) {
        LOGGER.info("Checking if user '{}' exists.", username);
        return userDetailsManager.userExists(username);
    }

    @PostMapping
    public ResponseEntity<String> createUser(@Valid @RequestBody UserRequest request) {
        LOGGER.debug("Started creating user '{}'.", request.getUsername());

        if (checkIfUserExists(request.getUsername())) {
            LOGGER.error("Username '{}' exists.", request.getUsername());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Username exists.");
        }

        String dbRole = request.getRole().toUpperCase();
        userDetailsManager.createUser(
                User.withUsername(request.getUsername())
                        .password(passwordEncoder.encode(request.getPassword()))
                        .roles(dbRole).build());
        LOGGER.info("User created successfully for '{}'.", request.getUsername());
        return new ResponseEntity<>(HttpStatus.CREATED);
    }

    @PutMapping
    public ResponseEntity<String> updateUser(@Valid UserRequest request) {
        LOGGER.debug("Started updating user '{}'.", request.getUsername());
        if (!checkIfUserExists(request.getUsername())) {
            LOGGER.error("Username '{}' does not exist and cannot be updated.", request.getUsername());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Username does not exist.");
        }
        String dbRole = request.getRole().toUpperCase();
        userDetailsManager.updateUser(
                User.withUsername(request.getUsername())
                        .password(passwordEncoder.encode(request.getPassword()))
                        .roles(dbRole).build());
        LOGGER.info("User updated successfully for '{}'.", request.getUsername());
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @DeleteMapping("/{username}")
    public ResponseEntity<String> deleteUser(@PathVariable String username) {
        LOGGER.debug("Started deleting user '{}'.", username);
        userDetailsManager.deleteUser(username);
        LOGGER.info("User deleted successfully for '{}'.", username);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

}
