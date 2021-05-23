package com.irene.authentication.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.io.Serializable;

@Data
@AllArgsConstructor
public class JwtResponse implements Serializable {

	private String jwt;
	@JsonProperty("expires_in")
	private String expiresIn;

}
