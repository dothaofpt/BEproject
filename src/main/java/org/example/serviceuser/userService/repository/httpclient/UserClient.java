package org.example.serviceuser.userService.repository.httpclient;

import org.example.serviceuser.userService.dto.RegisterCreationRequest;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "profile-service", url = "http://localhost:8082/auth")
public interface UserClient {
    @PostMapping(value = "/register", produces = MediaType.APPLICATION_JSON_VALUE)
    Object createRegister(@RequestBody RegisterCreationRequest request);
}
