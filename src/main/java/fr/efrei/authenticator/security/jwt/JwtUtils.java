package fr.efrei.authenticator.security.jwt;

import fr.efrei.authenticator.security.services.UserDetailsImpl;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.*;

import java.security.Key;
import java.security.KeyPair;
import java.util.Date;

@Component
public class JwtUtils {
    private final KeyPair keyPair = Jwts.SIG.RS256.keyPair().build();

    @Value("${auth.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    public Key getPublicKey(){
        return keyPair.getPublic();
    }

    public String generateJwtToken(Authentication authentication) {

        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        return Jwts.builder()
                .subject((userPrincipal.getUsername()))
                .claim("userId", userPrincipal.getId())
                .claim("email", userPrincipal.getEmail())
                .claim("roles", userPrincipal.getAuthorities())
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(keyPair.getPrivate())
                .compact();
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser().verifyWith(keyPair.getPublic()).build().parseSignedClaims(token).getPayload().getSubject();
    }

    public boolean validateJwtToken(String authToken) {
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
