package io.github.marianciuc.jwtsecurity.exceptions;

public class KeyDecodingException extends RuntimeException {
    public KeyDecodingException(String message) {
        super(message);
    }
}