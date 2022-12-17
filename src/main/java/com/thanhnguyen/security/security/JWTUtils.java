package com.thanhnguyen.security.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.thanhnguyen.security.constants.CONSTANTS;
import com.thanhnguyen.security.models.Role;
import com.thanhnguyen.security.models.User;
import com.thanhnguyen.security.services.UserService;
import lombok.SneakyThrows;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class JWTUtils {

    private final UserService userService;

    public JWTUtils(UserService userService) {
        this.userService = userService;
    }

    @SneakyThrows
    public Map<String, String> generateToken(String subject) {
        Map<String, String> tokens = new HashMap<>();
        User user = userService.getUser(subject);
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);

        JWTClaimsSet claimsAccessToken = new JWTClaimsSet
                .Builder()
                .subject(subject)
                .issuer("JOSE")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + CONSTANTS.VALIDATION_TIME_ACCESS_TOKEN))
                .claim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                .build();

        JWTClaimsSet claimsRefreshToken = new JWTClaimsSet
                .Builder()
                .subject(subject)
                .issuer("JOSE")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + CONSTANTS.VALIDATION_TIME_REFRESH_TOKEN))
                .build();

        JWSSigner signer = new MACSigner(CONSTANTS.MY_SECRET);
        SignedJWT accessToken = new SignedJWT(header, claimsAccessToken);
        SignedJWT refreshToken = new SignedJWT(header, claimsRefreshToken);
        accessToken.sign(signer);
        refreshToken.sign(signer);
        tokens.put("access_token", accessToken.serialize());
        tokens.put("refresh_token", refreshToken.serialize());
        return tokens;
    }

    @SneakyThrows
    public Map<String, String> generateToken(UserDetails user) {
        Map<String, String> tokens = new HashMap<>();
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);

        JWTClaimsSet claimsAccessToken = new JWTClaimsSet
                .Builder()
                .subject(user.getUsername())
                .issuer("JOSE")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + CONSTANTS.VALIDATION_TIME_ACCESS_TOKEN))
                .claim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .build();

        JWTClaimsSet claimsRefreshToken = new JWTClaimsSet
                .Builder()
                .subject(user.getUsername())
                .issuer("JOSE")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + CONSTANTS.VALIDATION_TIME_REFRESH_TOKEN))
                .build();

        JWSSigner signer = new MACSigner(CONSTANTS.MY_SECRET);
        SignedJWT accessToken = new SignedJWT(header, claimsAccessToken);
        SignedJWT refreshToken = new SignedJWT(header, claimsRefreshToken);
        accessToken.sign(signer);
        refreshToken.sign(signer);
        tokens.put("access_token", accessToken.serialize());
        tokens.put("refresh_token", refreshToken.serialize());
        return tokens;
    }

    @SneakyThrows
    public Boolean isValidToken(String token) {
        SignedJWT signedJWT = SignedJWT.parse(token);
        JWSVerifier verifier = new MACVerifier(CONSTANTS.MY_SECRET);
        return signedJWT.verify(verifier);
    }

    @SneakyThrows
    public String getSubject(String token) {
        SignedJWT signedJWT = SignedJWT.parse(token);
        return signedJWT.getJWTClaimsSet().getSubject();
    }

    public Map<String, String> refreshToken(String refreshToken) {
        String subject = getSubject(refreshToken);
        return generateToken(subject);
    }

    @SneakyThrows
    public List<GrantedAuthority> getAuthorities(String token) {
        SignedJWT signedJWT = SignedJWT.parse(token);
        return signedJWT.getJWTClaimsSet().getStringListClaim("roles")
                .stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}
