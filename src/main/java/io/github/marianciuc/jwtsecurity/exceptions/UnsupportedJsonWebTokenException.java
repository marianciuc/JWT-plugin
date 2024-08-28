package io.github.marianciuc.jwtsecurity.exceptions;

/**
 * The UnsupportedJsonWebTokenException class represents an exception that is thrown when a JSON Web Token (JWT) is unsupported.
 * @author Vladimir Marianciuc
 * @version 1.0
 */
public class UnsupportedJsonWebTokenException extends RuntimeException {
    public UnsupportedJsonWebTokenException(String message, String exception) {
        super(message + exception);
    }
}
