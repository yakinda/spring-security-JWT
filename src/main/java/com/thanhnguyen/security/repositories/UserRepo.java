package com.thanhnguyen.security.repositories;

import com.thanhnguyen.security.models.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepo extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
