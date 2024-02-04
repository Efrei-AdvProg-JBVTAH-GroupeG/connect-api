package fr.efrei.authenticator.service.impl;

import fr.efrei.authenticator.security.user.UserDetailsImpl;
import fr.efrei.authenticator.service.TokenService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.*;

import java.security.Key;
import java.security.KeyPair;
import java.util.Date;
import java.util.List;

@Component
public class JwtTokenServiceImpl implements TokenService {
    private final KeyPair keyPair = Jwts.SIG.RS256.keyPair().build();

    @Value("${auth.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    public Key getPublicKey(){
        return keyPair.getPublic();
    }

    public String generateToken(Authentication authentication) {

        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        List<String> authorities = userPrincipal.getAuthorities().stream().map(Object::toString).toList();

        return Jwts.builder()
                .subject((userPrincipal.getUsername()))
                .claim("id", userPrincipal.getId())
                .claim("email", userPrincipal.getEmail())
                .claim("roles", authorities)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(keyPair.getPrivate())
                .compact();
    }

    public String findUserNameFromToken(String token) {
        return Jwts.parser().verifyWith(keyPair.getPublic()).build().parseSignedClaims(token).getPayload().getSubject();
    }

    public boolean validateToken(String authToken) {
        try {
            Jwts.parser().verifyWith(keyPair.getPublic()).build().parseSignedClaims(authToken);
            return true;
        } catch (JwtException e) {
            System.err.println("Invalid JWT signature: {}" + e.getMessage());
        } catch (IllegalArgumentException e) {
            System.err.println("JWT claims string is empty: {}" + e.getMessage());
        }

        return false;
    }
}
