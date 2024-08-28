package io.github.marianciuc.jwtsecurity.service.impl;

import io.github.marianciuc.jwtsecurity.entity.JwtUser;
import io.github.marianciuc.jwtsecurity.enums.TokenType;
import io.github.marianciuc.jwtsecurity.exceptions.*;
import io.github.marianciuc.jwtsecurity.service.JsonWebTokenService;
import io.github.marianciuc.jwtsecurity.service.JwtUserDetails;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import static io.github.marianciuc.jwtsecurity.entity.JwtUser.ROLE_SERVICE;

/**
 * The `JsonWebTokenService` class is used to generate and parse JSON Web Tokens (JWTs) for authentication and authorization purposes.
 *
 * @author Vladimir Marianciuc
 * @version 2.0
 */
public class JsonWebTokenServiceImpl implements JsonWebTokenService {

    private static final String ROLE_CLAIM = "ROLE";
    private static final String ID_CLAIM = "ID";
    private static final String TOKEN_TYPE_CLAIM = "TOKEN_TYPE";
    private static final String JWT_EXPIRED_MESSAGE = "The provided JSON Web Token (JWT) has expired. Please request a new one.";
    private static final String UNSUPPORTED_JWT = "The provided JWT is not supported. Please ensure you're using a supported JWT format.";
    private static final String KEY_DECODING_ERROR = "There was an error attempting to decode the secret key: ";
    private static final String TOKEN_MATCHING_ERROR = "The provided token does not match the token type specified in the request. Please provide a matching token.";
    private static final String SUBJECT_ROLE_ERROR = "Subject and role can't be empty";

    private final String secretKey;
    private final String serviceName;
    private final Long accessExpiration;
    private final Long refreshExpiration;


    /**
     * JsonWebTokenService class constructor.
     *
     * @param serviceName       the name of service
     * @param secretKey         the secret key of the JWT.
     * @param accessExpiration  access token expiration time.
     * @param refreshExpiration refresh token expiration time.
     */
    public JsonWebTokenServiceImpl(String serviceName, String secretKey, Long accessExpiration, Long refreshExpiration) {
        this.secretKey = secretKey;
        this.accessExpiration = accessExpiration;
        this.refreshExpiration = refreshExpiration;
        this.serviceName = serviceName;
    }


    /**
     * Creates a JwtUserDetails object with the given subject, role, id, and token type.
     *
     * @param subject the subject of the user. Must not be empty or null.
     * @param role the role of the user. Must not be empty or null.
     * @param id the unique identifier (ID) of the user. Must not be null.
     * @param tokenType the type of the token. Must not be null.
     * @return the JwtUserDetails object representing the created user.
     * @throws IllegalArgumentException if the subject or role is null or empty.
     */
    public JwtUserDetails create(String subject, String role, UUID id, TokenType tokenType) {
        if(subject == null || role == null){
            throw new IllegalArgumentException(SUBJECT_ROLE_ERROR);
        }
        if(subject.isEmpty() || role.isEmpty()){
            throw new IllegalArgumentException(SUBJECT_ROLE_ERROR);
        }
        return new JwtUser(
                subject,
                role,
                id,
                tokenType
        );
    }

    /**
     * Generates an access token for the given user details.
     *
     * @param userDetails the JwtUserDetails object representing the user details.
     * @return a string representing the generated access token.
     */
    public String generateAccessToken(JwtUserDetails userDetails) {
        return this.generateToken(
                userDetails.getUsername(),
                userDetails.getRole(),
                TokenType.ACCESS_TOKEN,
                userDetails.getId()
        );
    }


    /**
     * Generates a refresh token for the given user details.
     *
     * @param userDetails the UserDetails object representing the user. Must not be null.
     * @return a string representing the generated refresh token.
     */
    public String generateRefreshToken(JwtUserDetails userDetails) {
        return this.generateToken(
                userDetails.getUsername(),
                userDetails.getRole(),
                TokenType.REFRESH_TOKEN,
                userDetails.getId()
        );
    }


    /**
     * Generates a service token for authentication.
     *
     * @return a string representing the generated service token.
     */
    public String generateServiceToken() {
        return this.generateToken(
                serviceName,
                ROLE_SERVICE,
                TokenType.ACCESS_TOKEN,
                UUID.randomUUID()
        );
    }


    /**
     * Parses the given token and returns the JwtUserDetails object representing the parsed token.
     *
     * @param token the token to parse. Must not be null or empty.
     * @return the JwtUserDetails object representing the parsed token.
     * @throws JwtSecurityException if the token type is not a refresh token.
     */
    public JwtUserDetails parseRefreshToken(String token) {
        JwtUserDetails jwtUser = this.parseToken(token);
        if (jwtUser.getType() != TokenType.REFRESH_TOKEN) throw new JwtSecurityException(TOKEN_MATCHING_ERROR);
        return jwtUser;
    }


    /**
     * Parses the given token and returns the JwtUserDetails object representing the parsed token.
     *
     * @param token the token to parse. Must not be null or empty.
     * @return the JwtUserDetails object representing the parsed token.
     * @throws JwtSecurityException if the token type is not an access token.
     */
    public JwtUserDetails parseAccessToken(String token) {
        JwtUserDetails jwtUser = this.parseToken(token);
        if (jwtUser.getType() != TokenType.ACCESS_TOKEN) throw new JwtSecurityException(TOKEN_MATCHING_ERROR);
        return jwtUser;
    }


    /**
     * Parses the given token and returns the JwtUserDetails object.
     *
     * @param token the token to parse. Must not be null or empty.
     * @return the JwtUserDetails object representing the parsed token.
     */
    private JwtUserDetails parseToken(String token) {
        Claims claims = parseJwtAndValidate(token);
        String subject = claims.getSubject();
        String role = (String) claims.get(ROLE_CLAIM);
        UUID id = UUID.fromString((String) claims.get(ID_CLAIM));
        TokenType tokenType = TokenType.valueOf(claims.get(TOKEN_TYPE_CLAIM, String.class));
        return create(subject, role, id, tokenType);
    }

    /**
     * Returns the expiration date for a given token type.
     *
     * @param type the token type to check the expiration for. Must not be null.
     * @return the expiration date for the given token type.
     */
    private Date getDateExpiration(TokenType type) {
        return new Date(System.currentTimeMillis() + (type.equals(TokenType.ACCESS_TOKEN) ? this.accessExpiration : this.refreshExpiration));
    }


    /**
     * Generates a JSON Web Token (JWT) with the given subject, role, token type, and UUID.
     *
     * @param subject the subject of the JWT. Must not be empty or null.
     * @param role the role claim of the JWT. Must not be empty or null.
     * @param type the token type of the JWT. Must not be null.
     * @param uuid the UUID claim of the JWT. Must not be null.
     * @return a JWT string.
     */
    private String generateToken(String subject, String role, TokenType type, UUID uuid) {
        return Jwts.builder()
                .subject(subject)
                .claim(ROLE_CLAIM, role)
                .claim(ID_CLAIM, uuid.toString())
                .claim(TOKEN_TYPE_CLAIM, type.toString())
                .expiration(this.getDateExpiration(type))
                .signWith(this.getPrivateKey())
                .compact();
    }


    /**
     * Parses and validates a JSON Web Token (JWT).
     *
     * @param jwt the JSON Web Token to parse and validate
     * @return the Claims object representing the payload of the JWT
     * @throws JsonWebTokenExpiredException     if the JWT has expired
     * @throws UnsupportedJsonWebTokenException if the JWT is unsupported
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
     * Retrieves the private key for creating JWTs.
     *
     * @return the SecretKey object representing the private key.
     * @throws UnexpectedKeyGenerationException if there is an unexpected error during key generation.
     * @throws KeyDecodingException           if there is an error decoding the secret key.
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
