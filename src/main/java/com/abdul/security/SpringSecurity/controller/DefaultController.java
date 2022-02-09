package com.abdul.security.SpringSecurity.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.abdul.security.SpringSecurity.configuration.JwtUtil;
import com.abdul.security.SpringSecurity.model.AuthenticationRequest;
import com.abdul.security.SpringSecurity.model.AuthenticationResponse;

@RestController
public class DefaultController {
	
	@Autowired
	private AuthenticationManager authManager;
	
	@Autowired
	private UserDetailsService userdetailService;
	
	@Autowired
	private JwtUtil jwtUtil;
	
	@RequestMapping("/hello")
	public String defaultMethod() {
		return "Spring default method invoked";
	}
	
	@RequestMapping(value = "/authenticate", method = RequestMethod.POST)
	public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest request) throws Exception{
		try {
			authManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));	
		}catch(BadCredentialsException e) {
			throw new Exception("incorrect username and password",e);
		}
		
		final UserDetails userDetail = userdetailService.loadUserByUsername(request.getUsername());
		
		 final String jwtToken = jwtUtil.generateToken(userDetail);
		 
		return ResponseEntity.ok(new AuthenticationResponse(jwtToken));
	}
	
}
