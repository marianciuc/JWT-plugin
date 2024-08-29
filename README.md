# JWT-Security
Jwt-Security is a Java library designed for generating, parsing, and validating JSON Web Tokens (JWTs). It provides a simple and secure way to manage authentication tokens in your Java applications, particularly in microservices environments.
## Features
- `JWT Generation`: Create secure access, refresh, and service tokens with customizable expiration times.
- `Token Parsing`: Easily parse JWTs to retrieve user details, roles, and other claims.
- `Validation`: Validate tokens to ensure they haven't expired or been tampered with.
- `Spring Security Integration`: Seamlessly integrates with Spring Security’s UserDetails for user management.
- `Role-Based Authentication`: Generate and parse tokens that include user roles.

## Installation
### Add the Dependency
To use the JwtPlugin in your project, add the following dependency to your `pom.xml` after publishing it to Maven Central or your private repository:

```
<dependency>
  <groupId>io.github.marianciuc</groupId>
  <artifactId>jwt-security</artifactId>
  <version>1.4.1</version>
</dependency>
```

### 2. Configure the Library
Create a configuration class in your Spring Boot project to set up the JWT service:

```JAVA
@Configuration
public class JwtConfig {

    @Value("${security.jwt.token.accessExpiration}")
    private Long accessExpiration;

    @Value("${security.jwt.token.refreshExpiration}")
    private Long refreshExpiration;

    @Value("${security.jwt.token.secret-key}")
    private String secretKey;

    @Value("${spring.application.name}")
    private String serviceName;

    @Bean
    public JsonWebTokenService jsonWebTokenService() {
        return new JsonWebTokenServiceImpl(serviceName, secretKey, accessExpiration, refreshExpiration);
    }

    @Bean
    public JsonWebTokenFilter jsonWebTokenFilter(JsonWebTokenService jsonWebTokenService, UserService userService) {
        return new JsonWebTokenFilter(jsonWebTokenService, userService);
    }

    @Bean
    public UserService userService() {
        return new UserServiceImpl();
    }
}

```
### 2. Set the Required Properties
Add the following properties to your application.properties or application.yml file:

```
security.jwt.token.accessExpiration=3600000 # 1 hour
security.jwt.token.refreshExpiration=86400000 # 1 day
security.jwt.token.secret-key=YourSecretKey encoded by base64 encoder
spring.application.name=YourServiceName
```

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue to discuss potential changes or improvements.

## License


This project is licensed under the Apache License 2.0 - see the LICENSE file for details.
