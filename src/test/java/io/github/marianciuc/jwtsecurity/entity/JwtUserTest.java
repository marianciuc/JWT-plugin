package io.github.marianciuc.jwtsecurity.entity;

import io.github.marianciuc.jwtsecurity.enums.TokenType;
import io.github.marianciuc.jwtsecurity.exceptions.IncorrectDataException;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JwtUserTest is a test class for the JwtUser class in the application.
 * It focuses on testing the `isService` method, checking if a JwtUser object
 * is considered a service based on its role.
 */
public class JwtUserTest {
    @Test
    public void testIsService_whenRoleIsService_returnsTrue() {
        JwtUser jwtUserWithServiceRole = new JwtUser("Subject", JwtUser.ROLE_SERVICE, UUID.randomUUID(), TokenType.ACCESS_TOKEN);
        assertTrue(jwtUserWithServiceRole.isService());
    }

    @Test
    public void testIsService_whenRoleIsNotService_returnsFalse() {
        JwtUser jwtUserWithDifferentRole = new JwtUser("Subject", "ROLE_USER", UUID.randomUUID(), TokenType.ACCESS_TOKEN);
        assertFalse(jwtUserWithDifferentRole.isService());
    }

    /**
     * Checks if the User is a Service.
     */
    @Test
    public void testIsService_whenRoleIsNull_returnsFalse() {
        JwtUser jwtUserWithNullRole = new JwtUser("Subject", null, UUID.randomUUID(), TokenType.ACCESS_TOKEN);
        assertFalse(jwtUserWithNullRole.isService());
    }

    /**
     * Test case to verify that the {@link JwtUser#getAuthorities()} method returns the service authority
     * when the role is "ROLE_SERVICE". This method checks if the collection of authorities contains the
     * expected service authority.
     * <p>
     * The expected behavior is that the {@link JwtUser#getAuthorities()} method should return a collection
     * of authorities that include the service authority when the role is "ROLE_SERVICE".
     *
     * @throws AssertionError if the test fails
     */
    @Test
    public void testGetAuthorities_whenRoleIsService_returnsServiceAuthority() {
        JwtUser jwtUserWithServiceRole = new JwtUser("Subject", JwtUser.ROLE_SERVICE, UUID.randomUUID(), TokenType.ACCESS_TOKEN);
        Collection<? extends GrantedAuthority> authorities = jwtUserWithServiceRole.getAuthorities();
        assertTrue(authorities.contains(new SimpleGrantedAuthority(JwtUser.ROLE_SERVICE)));
    }


    /**
     * Throws an {@link IncorrectDataException} when the role of the JwtUser is null.
     * This method verifies that the JwtUser has a role before retrieving the authorities.
     * If the role is null, it throws an exception indicating that there is no authority.
     *
     * @throws IncorrectDataException if the role of the JwtUser is null.
     */
    @Test
    public void testGetAuthorities_whenRoleIsNull_throwsException() {
        JwtUser jwtUserWithNullRole = new JwtUser("Subject", null, UUID.randomUUID(), TokenType.ACCESS_TOKEN);
        assertThrows(IncorrectDataException.class, jwtUserWithNullRole::getAuthorities);
    }
}
