package io.github.marianciuc.jwtsecurity.exceptions;

public class JwtSecurityException extends RuntimeException {
    public JwtSecurityException(String message) {
        super(message);
    }
}
