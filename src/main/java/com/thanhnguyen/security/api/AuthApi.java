package com.thanhnguyen.security.api;

import com.thanhnguyen.security.dto.UserRegisterDto;
import com.thanhnguyen.security.models.User;
import com.thanhnguyen.security.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthApi {

    private final UserService userService;

    @PostMapping("/register")
    ResponseEntity<User> register(@RequestBody UserRegisterDto user) {
        URI uri = URI
                .create(ServletUriComponentsBuilder.fromCurrentContextPath().path("api/v1/auth/register").toUriString());
        return ResponseEntity.created(uri).body(userService.signup(user.toUser()));
    }
}
