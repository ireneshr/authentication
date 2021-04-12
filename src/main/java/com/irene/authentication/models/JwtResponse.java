package com.irene.authentication.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.io.Serializable;
import java.util.Date;

@Data
public class JwtResponse implements Serializable {

	private String jwt;

	public JwtResponse(String jwt) {
		this.jwt = jwt;
	}

}
