package com.abdul.security.SpringSecurity.model;

public class AuthenticationResponse {
	
	private final String tokenJwt;
	
	public AuthenticationResponse(String tokenJwt) {
		super();
		this.tokenJwt = tokenJwt;
	}

	public String getTokenJwt() {
		return tokenJwt;
	}
	
}
