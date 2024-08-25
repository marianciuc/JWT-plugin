package io.github.marianciuc.jwtsecurity.service;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;
import java.util.UUID;

/**
 * The UserService class provides methods to retrieve information about the currently authenticated user.
 */
public class UserService {

    private static final String AUTH_ERROR_MSG = "Authentication failed";

    /**
     * Retrieves the UserDetails object for the currently authenticated user.
     *
     * @return The UserDetails object for the authenticated user.
     * @throws AuthenticationServiceException If authentication fails.
     */
    public UserDetails getUser() {
        return Optional.ofNullable(SecurityContextHolder.getContext().getAuthentication())
                .map(this::checkAndGetUser)
                .orElseThrow(() -> new AuthenticationServiceException(AUTH_ERROR_MSG));
    }

    /**
     * Checks if the given authentication object's principal is an instance of User and
     * returns the User object. If the principal is not an instance of User, an
     * AuthenticationServiceException is thrown.
     *
     * @param authentication The authentication object to check.
     * @return The User object from the authentication principal.
     * @throws AuthenticationServiceException If the authentication principal is not an instance of User.
     */
    private User checkAndGetUser(Authentication authentication) {
        if (authentication.getPrincipal() instanceof User) {
            return (User) authentication.getPrincipal();
        }
        throw new AuthenticationServiceException(AUTH_ERROR_MSG);
    }

    /**
     * Retrieves the UUID of the authenticated user.
     *
     * @return The UUID of the authenticated user.
     * @throws AuthenticationServiceException if authentication fails or the user does not have the required authority.
     */
    public UUID getUserId() {
        UserDetails userDetails = getUser();

        return userDetails.getAuthorities().stream()
                .filter(grantedAuthority -> "ROLE_SERVICE".equals(grantedAuthority.getAuthority()))
                .findFirst()
                .map(grantedAuthority -> UUID.fromString(userDetails.getUsername()))
                .orElseThrow(() -> new AuthenticationServiceException(AUTH_ERROR_MSG));
    }
}
