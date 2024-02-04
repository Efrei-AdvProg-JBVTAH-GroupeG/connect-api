package fr.efrei.authenticator.service;

import org.springframework.security.core.Authentication;

import java.security.Key;

public interface TokenService {

    public String generateToken(Authentication authentication);

    public Key getPublicKey();

    public boolean validateToken(String authToken);

    public String findUserNameFromToken(String token);
}
