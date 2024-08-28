package io.github.marianciuc.jwtsecurity.enums;

/**
 * The TokenType enumeration provides a representation of possible token types in the system. The tokens may be of type
 * access token or refresh token. This type can be obtained by calling the getType method on JwtUserDetails interface.
 * @version 1.0
 * @author Vladimir Marianciuc
 */
public enum TokenType {
    /**
     * Represents an access token.
     */
    ACCESS_TOKEN,
    /**
     * Represents a refresh token.
     */
    REFRESH_TOKEN
}
