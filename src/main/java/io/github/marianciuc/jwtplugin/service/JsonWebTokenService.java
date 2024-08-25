package io.github.marianciuc.jwtplugin.service;

import io.github.marianciuc.jwtplugin.entity.JwtUser;
import io.github.marianciuc.jwtplugin.entity.TokenType;
import io.github.marianciuc.jwtplugin.exceptions.*;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * The `JsonWebTokenService` class is used to generate and parse JSON Web Tokens (JWTs) for authentication and authorization purposes.
 *
 * @author Vladimir Marianciuc
 * @version 1.0
 */
public class JsonWebTokenService {

    private static final String SERVICE = "SERVICE";
    private static final String ROLE_SERVICE = "ROLE_SERVICE";
    private static final String ROLE_CLAIM = "ROLE";
    private static final String TOKEN_TYPE_CLAIM = "TOKEN_TYPE";
    private static final String JWT_EXPIRED_MESSAGE = "JWT has expired";
    private static final String UNSUPPORTED_JWT = "This JWT is not supported";
    private static final String KEY_DECODING_ERROR = "Key decoding error: ";
    private static final String TOKEN_MATCHING_ERROR = "Token does not match the request";
    private static final String ROLE_ERROR = "The user does not have any roles";
    private final String secretKey;
    private final Long accessExpiration;
    private final Long refreshExpiration;


    /**
     * JsonWebTokenService class constructor.
     *
     * @param secretKey         the secret key of the JWT.
     * @param accessExpiration  access token expiration time.
     * @param refreshExpiration refresh token expiration time.
     */
    public JsonWebTokenService(String secretKey, Long accessExpiration, Long refreshExpiration) {
        this.secretKey = secretKey;
        this.accessExpiration = accessExpiration;
        this.refreshExpiration = refreshExpiration;
    }


    /**
     * Creates a new instance of UserDetails.
     *
     * @param subject the subject of the user
     * @param role    the role of the user
     * @return a new instance of UserDetails populated with the given subject and role
     */
    public UserDetails create(String subject, String role) {
        List<GrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority(role));
        return new org.springframework.security.core.userdetails.User(subject, "", authorities);
    }

    /**
     * Returns the role of the user.
     *
     * @param userDetails the user details containing the authorities
     * @return the role of the user as a string
     * @throws UserDetailsException if the user details do not contain any authorities
     */
    private String getRole(UserDetails userDetails) {
        return userDetails.getAuthorities().stream()
                .findFirst()
                .map(GrantedAuthority::getAuthority).orElseThrow(() -> new UserDetailsException(ROLE_ERROR));
    }

    /**
     * Generates an access token based on the provided user details.
     *
     * @param userDetails the user details used to generate the token
     * @return the generated access token
     */
    public String generateAccessToken(UserDetails userDetails) {
        return this.generateToken(userDetails.getUsername(), this.getRole(userDetails), TokenType.ACCESS_TOKEN);
    }

    /**
     * Generates a refresh token for the given user details.
     *
     * @param userDetails the user details containing the username and role
     * @return a string representing the generated refresh token
     */
    public String generateRefreshToken(UserDetails userDetails) {
        return this.generateToken(userDetails.getUsername(), this.getRole(userDetails), TokenType.REFRESH_TOKEN);
    }

    /**
     * Generates JWTs for use between microservices.
     * {@code ROLE_SERVICE}
     *
     * @return the generated service token.
     */
    public String generateServiceToken() {
        return this.generateToken(SERVICE, ROLE_SERVICE, TokenType.ACCESS_TOKEN);
    }

    /**
     * Parses a refresh token and returns the corresponding UserDetails.
     *
     * @param token the refresh token to be parsed
     * @return the UserDetails object corresponding to the refresh token
     * @throws JwtSecurityException if the token is not a valid refresh token
     */
    public UserDetails parseRefreshToken(String token) {
        JwtUser jwtUser = this.parseToken(token);
        if (jwtUser.getType() != TokenType.REFRESH_TOKEN) throw new JwtSecurityException(TOKEN_MATCHING_ERROR);
        return this.create(jwtUser.getSubject(), jwtUser.getRole());
    }

    /**
     * Parses the given access token and returns the user details.
     *
     * @param token the access token to parse
     * @return the user details
     * @throws JwtSecurityException if the token type doesn't match TokenType.ACCESS_TOKEN
     */
    public UserDetails parseAccessToken(String token) {
        JwtUser jwtUser = this.parseToken(token);
        if (jwtUser.getType() != TokenType.ACCESS_TOKEN) throw new JwtSecurityException(TOKEN_MATCHING_ERROR);
        return this.create(jwtUser.getSubject(), jwtUser.getRole());
    }

    /**
     * Parses the given token and constructs a JwtUser object with the extracted information.
     *
     * @param token The token to be parsed.
     * @return A JwtUser object containing the subject, role, and token type extracted from the token.
     */
    private JwtUser parseToken(String token) {
        Claims claims = parseJwtAndValidate(token);
        String subject = claims.getSubject();
        String role = (String) claims.get(ROLE_CLAIM);
        TokenType tokenType = TokenType.valueOf(claims.get(TOKEN_TYPE_CLAIM, String.class));
        return new JwtUser(subject, role, tokenType);
    }

    /**
     * Returns the expiration date for the given token type.
     *
     * @param type The type of token (ACCESS_TOKEN or REFRESH_TOKEN)
     * @return The expiration date for the given token type.
     */
    private Date getDateExpiration(TokenType type) {
        return new Date(System.currentTimeMillis() + (type.equals(TokenType.ACCESS_TOKEN) ? this.accessExpiration : this.refreshExpiration));
    }

    /**
     * Generates a JWT token with the given subject, role, and token type.
     *
     * @param subject the subject of the token
     * @param role    the role of the user
     * @param type    the type of token (ACCESS_TOKEN or REFRESH_TOKEN)
     * @return a string representing the generated token
     */
    private String generateToken(String subject, String role, TokenType type) {
        return Jwts.builder()
                .subject(subject)
                .claim(ROLE_CLAIM, role)
                .claim(TOKEN_TYPE_CLAIM, type)
                .expiration(this.getDateExpiration(type))
                .signWith(this.getPrivateKey())
                .compact();
    }

    /**
     * Parses and validates a JSON Web Token (JWT).
     *
     * @param jwt the JSON Web Token to parse and validate
     * @return the claims contained within the JSON Web Token
     * @throws JsonWebTokenExpiredException     if the JSON Web Token has expired
     * @throws UnsupportedJsonWebTokenException if the JSON Web Token is unsupported
     */
    private Claims parseJwtAndValidate(String jwt) {
        try {
            JwtParser jwtParser = Jwts
                    .parser()
                    .verifyWith(getPrivateKey())
                    .build();
            return jwtParser.parseSignedClaims(jwt).getPayload();
        } catch (ExpiredJwtException e) {
            throw new JsonWebTokenExpiredException(JWT_EXPIRED_MESSAGE, e.getMessage());
        } catch (UnsupportedJwtException e) {
            throw new UnsupportedJsonWebTokenException(UNSUPPORTED_JWT, e.getMessage());
        }
    }

    /**
     * Retrieves the private key used for generating HMAC-based secret keys.
     *
     * @return the private key as a SecretKey object
     * @throws UnexpectedKeyGenerationException if an unexpected error occurs during key generation
     * @throws KeyDecodingException             if there is an error decoding the secret key
     */
    private SecretKey getPrivateKey() throws UnexpectedKeyGenerationException, KeyDecodingException {
        try {
            byte[] byteKey = Base64.getDecoder().decode(secretKey.getBytes());
            return Keys.hmacShaKeyFor(byteKey);
        } catch (IllegalArgumentException e) {
            throw new KeyDecodingException(KEY_DECODING_ERROR + e.getMessage());
        } catch (Exception e) {
            throw new UnexpectedKeyGenerationException(KEY_DECODING_ERROR + e.getMessage());
        }
    }
}
