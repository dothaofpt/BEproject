package org.example.orderservice.service;

import org.example.orderservice.entity.Order;

import java.util.List;

public interface OrderService {
    Order saveOrder(Order order);
    Order getOrderById(Long orderId);
    List<Order> getAllOrders();
    Order updateOrder(Long orderId, Order order);
    boolean deleteOrder(Long orderId);
}
