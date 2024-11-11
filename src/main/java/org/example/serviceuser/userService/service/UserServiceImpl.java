package org.example.serviceuser.userService.service;

import org.example.serviceuser.userService.dto.RegisterCreationRequest;
import org.example.serviceuser.userService.dto.UserDTO;
import org.example.serviceuser.userService.entity.User;
import org.example.serviceuser.userService.entity.UserRole;
import org.example.serviceuser.userService.jwt.JwtUtil;
import org.example.serviceuser.userService.mapper.RegisterMapper;
import org.example.serviceuser.userService.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RegisterMapper registerMapper;  // Inject RegisterMapper

    private final BCryptPasswordEncoder passwordEncoder;

    @Autowired
    public UserServiceImpl(BCryptPasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public Map<String, Object> registerUser(RegisterCreationRequest registerRequest) {
        Map<String, Object> response = new HashMap<>();

        // Kiểm tra nếu tên người dùng đã tồn tại
        if (findByUsername(registerRequest.getUsername()).isPresent()) {
            response.put("message", "Username already exists");
            return response;
        }

        // Chuyển đổi RegisterCreationRequest thành User qua RegisterMapper
        User user = registerMapper.toUser(registerRequest);

        // Kiểm tra nếu role là ADMIN thì chỉ cho phép một ADMIN duy nhất
        if (UserRole.ADMIN.equals(user.getRole())) {
            Optional<User> existingAdmin = userRepository.findByRole(UserRole.ADMIN);
            if (existingAdmin.isPresent()) {
                response.put("message", "Only one ADMIN allowed");
                return response;
            }
        }

        // Lưu người dùng mới vào cơ sở dữ liệu
        userRepository.save(user);

        // Phản hồi khi đăng ký thành công
        response.put("message", "User registered successfully");
        response.put("userId", user.getUserId());
        return response;
    }

    @Override
    public Map<String, String> loginUser(UserDTO userDTO) {
        Map<String, String> response = new HashMap<>();

        Optional<User> userOptional = findByUsername(userDTO.getUsername());

        if (userOptional.isPresent()) {
            User user = userOptional.get();
            if (passwordEncoder.matches(userDTO.getPassword(), user.getPassword())) {
                response.put("message", "Login successful");
                String token = jwtUtil.generateToken(userDTO.getUsername());
                response.put("token", token);
                response.put("role", user.getRole().toString());  // Trả về role
            } else {
                response.put("message", "Invalid username or password");
            }
        } else {
            response.put("message", "User not found");
        }

        return response;
    }
}

