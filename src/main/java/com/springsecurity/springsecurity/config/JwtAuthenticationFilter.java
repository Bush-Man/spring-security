package com.springsecurity.springsecurity.config;

import java.io.IOException;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

import com.springsecurity.springsecurity.jwt.JwtService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(
    @NonNull  HttpServletRequest request,
    @NonNull HttpServletResponse response, 
    @NonNull FilterChain filterChain
    )throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        

         if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
      
        
        final String jwt =  authHeader.substring(7);
        final String userEmail = jwtService.extractUserEmail(jwt);
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
       //if user is authenticated dont repeat the process again
        if(userEmail != null && authentication == null){
         UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);
        Boolean isTokenValid = jwtService.isTokenValid(jwt,userEmail);

         if(isTokenValid){ 
            //creates a new empty instance
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
            //adds the actual values
            authToken.setDetails(new  WebAuthenticationDetailsSource().buildDetails(request));
            // update security context holder
            SecurityContextHolder.getContext().setAuthentication(authToken);

         }
         filterChain.doFilter(request, response);

        }
            
        

        
    }
    



}
