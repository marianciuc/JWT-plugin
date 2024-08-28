package io.github.marianciuc.jwtsecurity.service;

import jakarta.servlet.http.HttpServletRequest;

/**
 * This interface is used to manage users by getting user details and setting user authentication.
 * @version 1.0
 * @author Vladimir Marianciuc
 */
public interface UserService {
    JwtUserDetails getUser();
    void setUserAuthentication(JwtUserDetails user, HttpServletRequest request);
}
