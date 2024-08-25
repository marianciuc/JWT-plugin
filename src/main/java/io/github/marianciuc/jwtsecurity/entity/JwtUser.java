package io.github.marianciuc.jwtsecurity.entity;

/**
 * JwtUser class represents a user in a JSON Web Token (JWT) context.
 */
public class JwtUser {

    private String subject;
    private String role;
    private TokenType type;

    public JwtUser(String subject, String role, TokenType tokenType) {
        this.subject = subject;
        this.role = role;
        this.type = tokenType;
    }

    public String getSubject() {
        return subject;
    }

    public String getRole() {
        return role;
    }

    public TokenType getType() {
        return type;
    }
}
