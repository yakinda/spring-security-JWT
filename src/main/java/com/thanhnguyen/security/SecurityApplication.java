package com.thanhnguyen.security;

import com.thanhnguyen.security.models.Role;
import com.thanhnguyen.security.models.User;
import com.thanhnguyen.security.services.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class SecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityApplication.class, args);
    }


    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner run(UserService userService) {
        return args -> {
            userService.saveRole(new Role(null, "ROLE_USER"));
            userService.saveRole(new Role(null, "ROLE_ADMIN"));
            userService.saveRole(new Role(null, "ROLE_MANAGER"));
            userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

            userService.saveUser(new User(null, "thanh", "123", "Thanh", new ArrayList<>()));
            userService.saveUser(new User(null, "cong", "112534adsa", "Cong", new ArrayList<>()));
            userService.saveUser(new User(null, "son", "114325", "Son", new ArrayList<>()));
            userService.saveUser(new User(null, "truong", "1654631asd", "Truong", new ArrayList<>()));

            userService.setRoleToUser("thanh", "ROLE_SUPER_ADMIN");
            userService.setRoleToUser("thanh", "ROLE_ADMIN");
            userService.setRoleToUser("thanh", "ROLE_USER");
            userService.setRoleToUser("cong", "ROLE_ADMIN");
            userService.setRoleToUser("cong", "ROLE_USER");
            userService.setRoleToUser("son", "ROLE_USER");
            userService.setRoleToUser("truong", "ROLE_USER");

        };
    }
}
