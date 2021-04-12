package com.irene.authentication.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class UserController {

    //The username is not case sensitive, applies for all methods
    private static final Logger LOGGER = LoggerFactory.getLogger(UserController.class);

    @Autowired
    @Qualifier("jdbcUserManager")
    private UserDetailsManager userDetailsManager;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @GetMapping("/{username}")
    public boolean checkIfUserExists(@PathVariable String username) {
        LOGGER.info("Checking if user '{}' exists.", username);
        return userDetailsManager.userExists(username);
    }

    @PostMapping("/{username}/{password}/{role}")
    public ResponseEntity<String> createUser(@PathVariable String username, @PathVariable String password,
                                             @PathVariable String role) {
        LOGGER.debug("Started creating user '{}'.", username);

        if (checkIfUserExists(username)) {
            LOGGER.error("Username '{}' exists.", username);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Username exists.");
        }

        String dbRole = role.toUpperCase();
        userDetailsManager.createUser(
                User.withUsername(username).password(passwordEncoder.encode(password)).roles(dbRole).build());
        LOGGER.info("User created successfully for '{}'.", username);
        return new ResponseEntity<>(HttpStatus.CREATED);
    }

    @PutMapping("/{username}/{password}/{role}")
    public ResponseEntity<String> updateUser(@PathVariable String username, @PathVariable String password,
                                             @PathVariable String role) {
        LOGGER.debug("Started updating user '{}'.", username);
        if (!checkIfUserExists(username)) {
            LOGGER.error("Username '{}' does not exist and cannot be updated.", username);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Username does not exist.");
        }
        String dbRole = role.toUpperCase();
        userDetailsManager.updateUser(
                User.withUsername(username).password(passwordEncoder.encode(password)).roles(dbRole).build());
        LOGGER.info("User updated successfully for '{}'.", username);
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
