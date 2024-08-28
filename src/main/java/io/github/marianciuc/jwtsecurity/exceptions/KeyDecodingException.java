package io.github.marianciuc.jwtsecurity.exceptions;

/**
 * KeyDecodingException is an exception that is thrown when there is an error
 * decoding the secret key.
 * @author Vladimir Marianciuc
 * @version 1.0
 */
public class KeyDecodingException extends RuntimeException {
    public KeyDecodingException(String message) {
        super(message);
    }
}