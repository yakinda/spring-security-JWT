package com.thanhnguyen.security;

import com.thanhnguyen.security.constants.CONSTANTS;
import com.thanhnguyen.security.models.Role;
import com.thanhnguyen.security.models.User;
import com.thanhnguyen.security.services.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.ArrayList;

@SpringBootApplication
public class SecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityApplication.class, args);
    }

    @Bean
    CommandLineRunner run(UserService userService) {
        return args -> {

            userService.saveRole(new Role(null, CONSTANTS.ROLE_USER));
            userService.saveRole(new Role(null, CONSTANTS.ROLE_ADMIN));
            userService.saveRole(new Role(null, CONSTANTS.ROLE_MANAGER));
            userService.saveRole(new Role(null, CONSTANTS.ROLE_SUPER_ADMIN));
            userService.saveUser(new User(null, "thanh", "123", "Thanh", new ArrayList<>()));
            userService.setRoleToUser("thanh", CONSTANTS.ROLE_SUPER_ADMIN);
            userService.setRoleToUser("thanh", CONSTANTS.ROLE_USER);

        };
    }
}
