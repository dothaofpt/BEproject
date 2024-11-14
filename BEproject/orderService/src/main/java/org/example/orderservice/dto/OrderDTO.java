package org.example.orderservice.dto;

import lombok.*;

import java.time.LocalDateTime;

@Getter
@Setter
@AllArgsConstructor
@ToString
public class OrderDTO {
private Long orderId;
private int quantity;
private Long shippingAddressId;
private LocalDateTime orderDate;
private  String status;


}
