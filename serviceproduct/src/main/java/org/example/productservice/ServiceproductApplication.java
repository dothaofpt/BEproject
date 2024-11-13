package org.example.productservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class ServiceproductApplication {

    public static void main(String[] args) {
        SpringApplication.run(ServiceproductApplication.class, args);
    }

}
