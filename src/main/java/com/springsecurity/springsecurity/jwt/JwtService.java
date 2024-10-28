package com.springsecurity.springsecurity.jwt;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    @Value("${secret.key")
    private String JWT_SECRET_KEY;
 
    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration;

    public String extractUserEmail(String jwt) {
        return extractClaim(jwt,Claims::getSubject);
    }

    private Date extractExpiration(String jwt){
        return extractClaim(jwt,Claims::getExpiration);
    }

    public boolean isExpired(String jwt){
        return extractExpiration(jwt).before(new Date());
    }
    public boolean isTokenValid(String jwt,String userEmail){
        return (!isExpired(jwt) && userEmail.equals(extractUserEmail(jwt)));
    }

    private Key getSignInKey(){
        byte[] keyBytes = Decoders.BASE64.decode(JWT_SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);

    }

    private <T> T extractClaim(String token,Function<Claims, T> claimsResolver){
        Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String jwt) {
        return Jwts
        .parserBuilder()
        .setSigningKey(getSignInKey())
        .build()
        .parseClaimsJws(jwt)
        .getBody();
            
    }
    public String generateToken(UserDetails userDetails){
        return buildToken(new HashMap<>(), userDetails);
    }

    private String buildToken(
    Map<String,Object> extraClaims,   
    UserDetails userDetails){
        return Jwts
          .builder()
          .setSubject(userDetails.getUsername())
          .setClaims(extraClaims)
          .setIssuedAt(new Date(System.currentTimeMillis()))
          .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
          .signWith(getSignInKey(),SignatureAlgorithm.HS256)
          .compact();
    }

}
