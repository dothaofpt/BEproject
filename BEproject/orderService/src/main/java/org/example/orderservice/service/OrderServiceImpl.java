package org.example.orderservice.service;

import org.example.orderservice.entity.Order;
import org.example.orderservice.repository.OrderRepository;
import org.example.orderservice.service.OrderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class OrderServiceImpl implements OrderService {

    private final OrderRepository orderRepository;

    @Autowired
    public OrderServiceImpl(OrderRepository orderRepository) {
        this.orderRepository = orderRepository;
    }

    @Override
    public Order saveOrder(Order order) {
        orderRepository.save(order);
        return order;
    }

    @Override
    public Order getOrderById(Long orderId) {
        return orderRepository.findById(orderId);
    }

    @Override
    public List<Order> getAllOrders() {
        return orderRepository.findAll();
    }

    @Override
    public Order updateOrder(Long orderId, Order order) {
        orderRepository.update(orderId, order);
        return order;
    }

    @Override
    public boolean deleteOrder(Long orderId) {
        return orderRepository.delete(orderId) > 0;
    }
}
