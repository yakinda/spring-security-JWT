package com.thanhnguyen.security.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.thanhnguyen.security.constants.CONSTANTS;
import com.thanhnguyen.security.models.Role;
import com.thanhnguyen.security.models.User;
import com.thanhnguyen.security.security.JWTUtils;
import com.thanhnguyen.security.services.UserService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Slf4j
public class UserResource implements BaseController {
    private final UserService userService;

    private final JWTUtils jwtUtils;

    @GetMapping("/users")
    @PreAuthorize("hasAuthority('" + CONSTANTS.ROLE_SUPER_ADMIN + "')")
    ResponseEntity<List<User>> getUsers() {
        log.info(this.uid());
        return ResponseEntity.ok().body(userService.getUsers());
    }

    @PostMapping("user/create")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN','ROLE_SUPER_ADMIN')")
    ResponseEntity<User> createUser(@RequestBody User user) {
        URI uri = URI
                .create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/create").toUriString());
        return ResponseEntity.created(uri).body(userService.saveUser(user));
    }

    @PreAuthorize("hasAnyAuthority('ROLE_SUPER_ADMIN')")
    @PostMapping("role/create")
    ResponseEntity<Role> createUser(@RequestBody Role role) {
        URI uri = URI
                .create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/create").toUriString());
        return ResponseEntity.created(uri).body(userService.saveRole(role));
    }

    @PreAuthorize("hasAnyAuthority('ROLE_SUPER_ADMIN')")
    @PostMapping("/role/addUser")
    ResponseEntity<?> addRoleToUser(@RequestBody RoleUser data) {
        userService.setRoleToUser(data.getUsername(), data.getRoleName());
        return ResponseEntity.ok().build();
    }

    @PreAuthorize("hasAuthority('ROLE_USER')")
    @PostMapping("/user/edit")
    ResponseEntity<?> editUser(@RequestBody User user, @RequestAttribute("username") String username) {
        userService.editUser(username, user);
        return ResponseEntity.ok().build();
    }

    @GetMapping("token/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorizationHeader = request.getHeader(AUTHORIZATION);
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            try {
                String refresh_token = authorizationHeader.split(" ")[1];
                if (!jwtUtils.isValidToken(refresh_token)) {
                    throw new ResponseStatusException(UNAUTHORIZED, "Invalid Token");
                }
                Map<String, String> tokens = jwtUtils.refreshToken(refresh_token);
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), tokens);
            } catch (Exception exception) {
                response.setHeader("error", exception.getMessage());
                response.setStatus(FORBIDDEN.value());
                Map<String, String> error = new HashMap<>();
                error.put("error", exception.getMessage());
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), error);
            }
        } else {
            throw new RuntimeException("Refresh token is missing");
        }
    }
}

@Data
class RoleUser {
    private String username;
    private String roleName;

}
