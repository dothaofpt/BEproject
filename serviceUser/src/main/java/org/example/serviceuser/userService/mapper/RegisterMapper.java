package org.example.serviceuser.userService.mapper;

import org.example.serviceuser.userService.dto.RegisterCreationRequest;
import org.example.serviceuser.userService.entity.User;
import org.example.serviceuser.userService.entity.UserRole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class RegisterMapper {

    private final BCryptPasswordEncoder passwordEncoder;

    @Autowired
    public RegisterMapper(BCryptPasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    // Phương thức để chuyển đổi từ RegisterCreationRequest sang User
    public User toUser(RegisterCreationRequest registerRequest) {
        User user = new User();
        user.setUsername(registerRequest.getUsername());
        user.setPassword(passwordEncoder.encode(registerRequest.getPassword())); // mã hóa mật khẩu
        user.setEmail(registerRequest.getEmail());

        // Xác định vai trò của người dùng
        UserRole role = UserRole.CUSTOMER; // mặc định là CUSTOMER
        if ("ADMIN".equalsIgnoreCase(registerRequest.getRole())) {
            role = UserRole.ADMIN;
        } else if ("STAFF".equalsIgnoreCase(registerRequest.getRole())) {
            role = UserRole.STAFF;
        }
        user.setRole(role);

        return user;
    }
}

