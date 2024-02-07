package com.najot.dasr11.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${application.security.jwt.secret-key}") // key
    private String sekretKey;

    @Value("${application.security.jwt.expiration}") // 1 kun
    private long tokenExpTime;

    @Value("${application.security.jwt.refresh-token.expiration}")// 7 kun
    private long refTokenExpTime;


    public String extractUsername(String token){
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpTime(String token){
        return extractClaim(token, Claims::getExpiration);
    }

    private  <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInkey())
                .build()
                .parseClaimsJwt(token)
                .getBody();
    }

    private Key getSignInkey(){
        byte[] keyBytes = Decoders.BASE64.decode(sekretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }


}
