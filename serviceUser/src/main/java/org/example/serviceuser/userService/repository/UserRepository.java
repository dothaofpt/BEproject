package org.example.serviceuser.userService.repository;

import org.example.serviceuser.userService.entity.User;
import org.example.serviceuser.userService.entity.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    Optional<User> findByRole(UserRole userRole);
}