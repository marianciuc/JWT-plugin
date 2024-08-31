# JWT-Security
JWT-Security is a Java library designed to simplify the generation and validation of JSON Web Tokens (JWT) in a microservices architecture. The library integrates with Spring Security, providing secure user authentication and request filtering without the need for repeated configuration in each microservice.
## Features
- `JWT Generation`:  Create customizable tokens with expiration times, user roles, and additional claims.
- `Token Parsing`: Easily parse JWTs to retrieve user details, roles, and other claims.
- `Spring Security Integration`: Seamlessly integrates with Spring Security’s UserDetails for user management.
- `Role-Based Authentication`: Generate and parse tokens that include user roles.
- `Decentralized Token Verification`: Independent token validation across microservices for better performance and scalability.
- `User Service Support`: Customizable user service integration for handling user-related operations.

## Installation

Add the following dependency to your pom.xml:
```
<dependency>
  <groupId>io.github.marianciuc</groupId>
  <artifactId>jwt-security</artifactId>
  <version>1.4.1</version>
</dependency>
```

## 2. Configuration
To configure JWT-Security in your Spring Boot application, you need to set up the required properties in your application.properties or application.yml file:

### application.properties
```
security.jwt.token.accessExpiration=3600
security.jwt.token.refreshExpiration=7200
security.jwt.token.secret-key=your-secret-key
spring.application.name=your-service-name
```
## Integration
### Create Web Security Configuration
Create a class that extends WebSecurityConfigurerAdapter and configure the JWT filter:

```JAVA
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

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

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .authorizeRequests()
                .antMatchers("/public/**").permitAll()
                .anyRequest().authenticated()
            .and()
            .addFilterBefore(jsonWebTokenFilter(jsonWebTokenService(), userService()), UsernamePasswordAuthenticationFilter.class);
    }
}
```

## Contributing
We welcome contributions! Please feel free to submit a pull request or open an issue for discussion.
## Contact
For any questions or support, please reach out to [marianciuc.work@gmail.com].
## License
This project is licensed under the Apache License 2.0 - see the LICENSE file for details.
