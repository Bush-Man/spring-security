package com.springsecurity.springsecurity.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import com.springsecurity.springsecurity.dto.AuthenticationResponse;
import com.springsecurity.springsecurity.dto.LoginRequest;
import com.springsecurity.springsecurity.dto.RegisterRequest;
import com.springsecurity.springsecurity.jwt.JwtService;
import com.springsecurity.springsecurity.repository.UserRepository;
import com.springsecurity.springsecurity.user.Role;
import com.springsecurity.springsecurity.user.User;



@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    public AuthenticationController(PasswordEncoder passwordEncoder,UserRepository userRepository, AuthenticationManager authenticationManager,JwtService JwtService) {
        
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
        this.jwtService = JwtService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterRequest registerRequest){
        
         User user = new User();
         user.setFirstName(registerRequest.getFirstname());
         user.setLastName(registerRequest.getLastname());
         user.setEmail(registerRequest.getEmail());
         user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
         user.setRole(Role.USER); 
         
        userRepository.save(user);
        return new ResponseEntity<>("User Created Successfully",HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody LoginRequest request) {
        String email = request.getEmail();
        String password = request.getPassword();
        System.out.println("Email: " + email + " Password: " + password);
        System.out.println("...................................................");
        System.out.print(request);
        System.out.println("...................................................");

        System.out.printf(email);
        System.out.printf("Password", password);
        
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email,password));

      var user = userRepository.findByEmail(email).orElseThrow();
      var jwtToken = jwtService.generateToken(user);
      AuthenticationResponse response = new AuthenticationResponse();
      response.setToken(jwtToken);
         return new ResponseEntity<>(response ,HttpStatus.CREATED);

    }
    


    
}
