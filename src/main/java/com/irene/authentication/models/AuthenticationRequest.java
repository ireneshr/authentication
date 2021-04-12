package com.irene.authentication.models;

import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import javax.validation.constraints.Pattern;

@Data
public class AuthenticationRequest {

    @ApiModelProperty(value = "User's email.")
    private String email;
    @ApiModelProperty(value = "User identifier.")
    private String username;
    @ApiModelProperty(value = "User password.")
    private String password;

}
