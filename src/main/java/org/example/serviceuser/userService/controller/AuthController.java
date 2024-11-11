package org.example.serviceuser.userService.controller;

import org.example.serviceuser.userService.dto.RegisterCreationRequest;
import org.example.serviceuser.userService.dto.UserDTO;
import org.example.serviceuser.userService.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserService userService;

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> registerUser(@RequestBody RegisterCreationRequest registerRequest) {  // Chuyển từ UserDTO thành RegisterCreationRequest
        Map<String, Object> response = userService.registerUser(registerRequest);  // Gọi phương thức registerUser với RegisterCreationRequest

        // Kiểm tra và trả về các thông báo lỗi khi tên người dùng đã tồn tại hoặc khi đã có ADMIN
        if (response.containsKey("message") && response.get("message").equals("Username already exists")) {
            return ResponseEntity.status(400).body(response);
        }
        if (response.containsKey("message") && response.get("message").equals("Only one ADMIN allowed")) {
            return ResponseEntity.status(403).body(response);  // Trả về lỗi khi vượt quá giới hạn ADMIN
        }
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> loginUser(@RequestBody UserDTO userDTO) {
        Map<String, String> response = userService.loginUser(userDTO);

        if (response.containsKey("message") && response.get("message").equals("Invalid username or password")) {
            return ResponseEntity.status(401).body(response);
        }

        if (response.containsKey("message") && response.get("message").equals("User not found")) {
            return ResponseEntity.status(404).body(response);
        }

        return ResponseEntity.ok(response);
    }
}
