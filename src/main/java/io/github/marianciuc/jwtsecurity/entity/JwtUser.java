package io.github.marianciuc.jwtsecurity.entity;

import io.github.marianciuc.jwtsecurity.enums.TokenType;
import io.github.marianciuc.jwtsecurity.exceptions.IncorrectDataException;
import io.github.marianciuc.jwtsecurity.service.JwtUserDetails;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * JwtUser class represents a user in the application with JWT specific details.
 * Note: For JwtUsers, the account is always non-expired, non-locked, credentials non-expired, enabled by default.
 * JwtUser instances do not have a password associated with them.
 *
 * @author Vladimir Marianciuc
 * @version 1.0
 */
public class JwtUser implements JwtUserDetails {

    public static final String ROLE_SERVICE = "ROLE_SERVICE";

    private static final String NO_PASSWORD = "No Password";
    private static final boolean DEFAULT_USER_SETTING = true;

    private final UUID id;
    private final String role;
    private final String subject;
    private final TokenType type;

    /**
     * JwtUser class represents a user in the application with JWT specific details.
     */
    public JwtUser(String subject, String role, UUID id, TokenType type) {
        this.subject = subject;
        this.role = role;
        this.id = id;
        this.type = type;
    }

    /**
     * Returns the role of the user.
     *
     * @return a String that represents the role of the user.
     */
    public String getRole() {
        return role;
    }

    /**
     * Returns the type of the token.
     *
     * @return the TokenType that represents the type of the token.
     */
    public TokenType getType() {
        return type;
    }

    /**
     * Checks if the User is a Service.
     *
     * @return true if the User is a Service, else false.
     */
    @Override
    public boolean isService() {
        if (role != null) return role.equals(ROLE_SERVICE);
        return false;
    }

    /**
     * Retrieves the unique identifier (ID) of the user.
     *
     * @return a UUID that represents the unique ID of the user.
     */
    @Override
    public UUID getId() {
        return this.id;
    }

    /**
     * Retrieves the authorities (roles) granted to the user.
     *
     * @return a Collection of GrantedAuthority objects that represent the user's authorities.
     * Each authority represents a role that the user has.
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (role != null) return List.of(new SimpleGrantedAuthority(role));
        else throw new IncorrectDataException("No Authority");
    }


    /**
     * Retrieves the password associated with the user.
     *
     * @return a String representing the password. For JwtUser instances, the password is always "No Password".
     */
    @Override
    public String getPassword() {
        return NO_PASSWORD;
    }

    /**
     * Returns the username of the JwtUser.
     *
     * @return a String that represents the username of the JwtUser.
     */
    @Override
    public String getUsername() {
        return subject;
    }

    /**
     * Checks if the account is non-expired.
     *
     * @return true if the account is non-expired, false otherwise.
     */
    @Override
    public boolean isAccountNonExpired() {
        return DEFAULT_USER_SETTING;
    }

    /**
     * Checks if the user account is locked.
     *
     * @return true if the user account is not locked, false otherwise.
     * @see JwtUserDetails
     */
    @Override
    public boolean isAccountNonLocked() {
        return DEFAULT_USER_SETTING;
    }

    /**
     * Checks if the user's credentials are non-expired.
     *
     * @return {@code true} if the user's credentials are non-expired, {@code false} otherwise
     * @see JwtUserDetails
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return DEFAULT_USER_SETTING;
    }

    /**
     * Checks if the user account is enabled.
     *
     * @return true if the user account is enabled, false otherwise.
     */
    @Override
    public boolean isEnabled() {
        return DEFAULT_USER_SETTING;
    }
}
