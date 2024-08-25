package io.github.marianciuc.jwtplugin.exceptions;

public class JwtSecurityException extends RuntimeException {
    public JwtSecurityException(String message) {
        super(message);
    }
}
