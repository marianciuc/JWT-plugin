package io.github.marianciuc.jwtsecurity.exceptions;

/**
 * Exception thrown when a JWT security-related error occurs.
 * @author Vladimir Marianciuc
 * @version 1.0
 */
public class JwtSecurityException extends RuntimeException {
    public JwtSecurityException(String message) {
        super(message);
    }
}
