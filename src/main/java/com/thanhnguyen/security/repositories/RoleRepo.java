package com.thanhnguyen.security.repositories;

import com.thanhnguyen.security.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepo extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
