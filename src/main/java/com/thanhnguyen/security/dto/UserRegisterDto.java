package com.thanhnguyen.security.dto;

import com.thanhnguyen.security.models.User;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;

@Getter
@Setter
public class UserRegisterDto {
    private String username;
    private String password;
    private String name;

    public UserRegisterDto(String username, String password, String name) {
        this.username = username;
        this.password = password;
        this.name = name;
    }

    public User toUser() {
        User user = new User();
        user.setUsername(this.username);
        user.setPassword(this.password);
        user.setName(this.name);
        user.setRoles(new ArrayList<>());
        return user;
    }
}

