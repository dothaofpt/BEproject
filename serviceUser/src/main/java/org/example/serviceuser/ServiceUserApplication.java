package org.example.serviceuser;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@EnableDiscoveryClient
@EnableJpaRepositories(basePackages = "org.example.serviceuser.userService.repository")
@EntityScan(basePackages = "org.example.serviceuser.userService.entity")
public class ServiceUserApplication {

	public static void main(String[] args) {
		SpringApplication.run(ServiceUserApplication.class, args);
	}
}
