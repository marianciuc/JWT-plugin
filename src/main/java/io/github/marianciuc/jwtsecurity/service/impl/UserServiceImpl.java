package io.github.marianciuc.jwtsecurity.service.impl;

import io.github.marianciuc.jwtsecurity.service.JwtUserDetails;
import io.github.marianciuc.jwtsecurity.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

import java.util.Optional;

/**
 * The UserService class provides methods to retrieve information about the currently authenticated user.
 * @version 1.0
 * @author Vladimir Marianciuc
 */
public class UserServiceImpl implements UserService {

    private static final String AUTH_ERROR_MSG = "Authentication failed";

    /**
     * Retrieves the UserDetails object for the currently authenticated user.
     *
     * @return The UserDetails object for the authenticated user.
     * @throws AuthenticationServiceException If authentication fails.
     */
    public JwtUserDetails getUser() {
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
    private JwtUserDetails checkAndGetUser(Authentication authentication) {
        if (authentication.getPrincipal() instanceof JwtUserDetails) {
            return (JwtUserDetails) authentication.getPrincipal();
        }
        throw new AuthenticationServiceException(AUTH_ERROR_MSG);
    }

    /**
     * Sets the user's authentication in the security context.
     *
     * @param user The user details of the authenticated user.
     * @param request The HTTP servlet request.
     */
    public void setUserAuthentication(JwtUserDetails user, HttpServletRequest request) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                user, null, user.getAuthorities());
        usernamePasswordAuthenticationToken
                .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
    }
}
