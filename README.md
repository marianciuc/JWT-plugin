# JwtPlugin
JwtPlugin is a Java library designed for generating, parsing, and validating JSON Web Tokens (JWTs). It provides a simple and secure way to manage authentication tokens in your Java applications, particularly in microservices environments.
## Features
- `JWT Generation`: Create secure access, refresh, and service tokens with customizable expiration times.
- `Token Parsing`: Easily parse JWTs to retrieve user details, roles, and other claims.
- `Validation`: Validate tokens to ensure they haven't expired or been tampered with.
- `Spring Security Integration`: Seamlessly integrates with Spring Security’s UserDetails for user management.
- `Role-Based Authentication`: Generate and parse tokens that include user roles.

## Installation
To use the JwtPlugin in your project, add the following dependency to your `pom.xml` after publishing it to Maven Central or your private repository:

```
<dependency>
  <groupId>io.github.marianciuc.jwtplugin</groupId>
  <artifactId>jwt-plugin</artifactId>
  <version>1.0-SNAPSHOT</version>
</dependency>
```
## Usage

### 1. Initialization
To create an instance of JsonWebTokenService, you need to provide the secretKey, accessExpiration, and refreshExpiration:
```JAVA
JsonWebTokenService jwtService = new JsonWebTokenService("your-secret-key encoded by base64",3600000L,86400000L);
```
### 2. Generating Tokens
#### Generate Access Token
```java
UserDetails userDetails = jwtService.create("username", "ROLE_USER");
String accessToken = jwtService.generateAccessToken(userDetails);
```
#### Generate Refresh Token
```java
String refreshToken = jwtService.generateRefreshToken(userDetails);
```
#### Generate Service Token
For internal microservice communication:
```java
String serviceToken = jwtService.generateServiceToken();
```

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue to discuss potential changes or improvements.

## License


This project is licensed under the Apache License 2.0 - see the LICENSE file for details.
