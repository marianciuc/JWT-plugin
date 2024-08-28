package io.github.marianciuc.jwtsecurity.exceptions;

/**
 * The JsonWebTokenExpiredException class represents an exception that is thrown when a JSON Web Token (JWT) has expired.
 * @author Vladimir Marianciuc
 * @version 1.0
 */
public class JsonWebTokenExpiredException extends RuntimeException {
    public JsonWebTokenExpiredException(String message, String exception) {
        super(message + exception);
    }
}
