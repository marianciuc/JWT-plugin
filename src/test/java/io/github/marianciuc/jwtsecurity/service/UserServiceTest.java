package io.github.marianciuc.jwtsecurity.service;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;

import java.util.Collections;
import java.util.UUID;

/**
 * The UserServiceTest class contains tests for the UserService class.
 */
public class UserServiceTest {

    /**
     * Tests the getUser method in the UserService class when the Authentication object is null.
     */
    @Test
    public void getUser_AuthenticationIsNull_ThrowsAuthenticationServiceException() {
        SecurityContextHolder.getContext().setAuthentication(null);
        UserService userService = new UserService();

        Assertions.assertThrows(AuthenticationServiceException.class, userService::getUser);
    }

    /**
     * Tests the getUser method in the UserService class when the Authentication object's principal is not User.
     */
    @Test
    public void getUser_AuthenticationPrincipalIsNotUser_ThrowsAuthenticationServiceException() {
        String nonUserPrincipal = "nonUserPrincipal";
        TestingAuthenticationToken authenticationToken = new TestingAuthenticationToken(nonUserPrincipal, null);
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        UserService userService = new UserService();

        Assertions.assertThrows(AuthenticationServiceException.class, userService::getUser);
    }

    /**
     * Tests the getUser method in the UserService class when the Authentication object's principal is User.
     */
    @Test
    public void getUser_AuthenticationPrincipalIsUser_ReturnsUser() {
        User user = new User("username", "password", Collections.emptyList());
        TestingAuthenticationToken authenticationToken = new TestingAuthenticationToken(user, null, Collections.emptyList());
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        UserService userService = new UserService();

        User result = (User) userService.getUser();

        Assertions.assertNotNull(result);
        Assertions.assertEquals("username", result.getUsername());
        Assertions.assertEquals("password", result.getPassword());
    }
    /**
     * Tests the getUserId method in the UserService class when the Authentication object is null.
     */
    @Test
    public void getUserId_AuthenticationIsNull_ThrowsAuthenticationServiceException() {
        SecurityContextHolder.getContext().setAuthentication(null);
        UserService userService = new UserService();
        Assertions.assertThrows(AuthenticationServiceException.class, userService::getUserId);
    }

    /**
     * Tests the getUserId method in the UserService class when the Authentication object's principal is not User.
     */
    @Test
    public void getUserId_AuthenticationPrincipalIsNotUser_ThrowsAuthenticationServiceException() {
        String nonUserPrincipal = "nonUserPrincipal";
        TestingAuthenticationToken authenticationToken = new TestingAuthenticationToken(nonUserPrincipal, null);
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        UserService userService = new UserService();
        Assertions.assertThrows(AuthenticationServiceException.class, userService::getUserId);
    }

    /**
     * Tests the getUserId method in the UserService class when the Authentication object's principal is User
     * but does not have "ROLE_SERVICE" authority.
     */
    @Test
    public void getUserId_AuthenticationPrincipalIsUserNoRoleService_ThrowsAuthenticationServiceException() {
        User user = new User("username", "password", Collections.emptyList());
        TestingAuthenticationToken authenticationToken = new TestingAuthenticationToken(user, null, Collections.emptyList());
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        UserService userService = new UserService();
        Assertions.assertThrows(AuthenticationServiceException.class, userService::getUserId);
    }

    /**
     * Tests the getUserId method in the UserService class when the Authentication object's principal is User
     * and has "ROLE_SERVICE" authority.
     */
    @Test
    public void getUserId_AuthenticationPrincipalIsUserAndRoleService_ReturnsUUID() {
        UUID uuid = UUID.randomUUID();
        User user = new User(uuid.toString(), "UUID", Collections.singletonList(new SimpleGrantedAuthority("ROLE_SERVICE")));
       TestingAuthenticationToken authenticationToken = new TestingAuthenticationToken(user, null, user.getAuthorities());
       SecurityContextHolder.getContext().setAuthentication(authenticationToken);
       UserService userService = new UserService();

       UUID result = userService.getUserId();

       Assertions.assertNotNull(result);
       Assertions.assertEquals(uuid, result);
   }
}
