package org.example.orderservice.controller;

import org.example.orderservice.entity.Order;
import org.example.orderservice.service.OrderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/orders")
public class OrderController {

    private final OrderService orderService;

    @Autowired
    public OrderController(OrderService orderService) {
        this.orderService = orderService;
    }

    @PostMapping
    public Order createOrder(@RequestBody Order order) {
        return orderService.saveOrder(order);
    }

    @GetMapping("/{id}")
    public Order getOrderById(@PathVariable("id") Long orderId) {
        return orderService.getOrderById(orderId);
    }

    @GetMapping
    public List<Order> getAllOrders() {
        return orderService.getAllOrders();
    }

    @PutMapping("/{id}")
    public Order updateOrder(@PathVariable("id") Long orderId, @RequestBody Order order) {
        return orderService.updateOrder(orderId, order);
    }

    @DeleteMapping("/{id}")
    public String deleteOrder(@PathVariable("id") Long orderId) {
        boolean isDeleted = orderService.deleteOrder(orderId);
        return isDeleted ? "Order deleted successfully." : "Order deletion failed.";
    }
}
