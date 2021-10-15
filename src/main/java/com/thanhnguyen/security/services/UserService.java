package com.thanhnguyen.security.services;

import com.thanhnguyen.security.models.Role;
import com.thanhnguyen.security.models.User;

import java.util.List;

public interface UserService {
    User saveUser(User user);

    Role saveRole(Role role);

    void setRoleToUser(String username, String roleName);

    User getUser(String username);

    User editUser(String username,User userRequest);

    List<User> getUsers();
}
