package org.example.serviceuser.userService.service;

import org.example.serviceuser.userService.dto.RegisterCreationRequest;
import org.example.serviceuser.userService.dto.UserDTO;
import org.example.serviceuser.userService.entity.User;

import java.util.Map;
import java.util.Optional;

public interface UserService {
    Optional<User> findByUsername(String username);
    Map<String, Object> registerUser(RegisterCreationRequest registerRequest);
    Map<String, String> loginUser(UserDTO userDTO);
}

