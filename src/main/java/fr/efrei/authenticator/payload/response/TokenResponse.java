package fr.efrei.authenticator.payload.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
public class TokenResponse {
    @Getter@Setter
    private String Token;
}
