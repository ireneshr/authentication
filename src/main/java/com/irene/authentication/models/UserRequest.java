package com.irene.authentication.models;

import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;

@Data
public class UserRequest {

    @Email(message = "Email should be valid.")
    @ApiModelProperty(value = "User's email.")
    private String email;
    @NotBlank
    @ApiModelProperty(value = "User identifier.")
    private String username;
    @NotBlank
    @ApiModelProperty(value = "User password.")
    private String password;
    @NotBlank
    @ApiModelProperty(value = "User role.")
    private String role;

}
