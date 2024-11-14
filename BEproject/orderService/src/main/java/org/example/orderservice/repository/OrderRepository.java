package org.example.orderservice.repository;

import org.example.orderservice.entity.Order;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Repository
public class OrderRepository {

    private final NamedParameterJdbcTemplate jdbcTemplate;

    @Autowired
    public OrderRepository(NamedParameterJdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }


    public int save(Order order) {
        String sql = "INSERT INTO orders (quantity, shipping_address_id, order_date, status) VALUES (:quantity, :shippingAddressId, :orderDate, :status)";


        Map<String, Object> params = new HashMap<>();
        params.put("quantity", order.getQuantity());
        params.put("shippingAddressId", order.getShippingAddressId());
        params.put("orderDate", order.getOrderDate());
        params.put("status", order.getStatus());

        return jdbcTemplate.update(sql, params);
    }


    public Order findById(Long orderId) {
        String sql = "SELECT * FROM orders WHERE order_id = :orderId";

        Map<String, Object> params = new HashMap<>();
        params.put("orderId", orderId);

        return jdbcTemplate.queryForObject(sql, params, new OrderRowMapper());
    }


    public List<Order> findAll() {
        String sql = "SELECT * FROM orders";
        return jdbcTemplate.query(sql, new OrderRowMapper());
    }


    public int update(Long orderId, Order order) {
        String sql = "UPDATE orders SET quantity = :quantity, shipping_address_id = :shippingAddressId, order_date = :orderDate, status = :status WHERE order_id = :orderId";

        Map<String, Object> params = new HashMap<>();
        params.put("orderId", orderId);
        params.put("quantity", order.getQuantity());
        params.put("shippingAddressId", order.getShippingAddressId());
        params.put("orderDate", order.getOrderDate());
        params.put("status", order.getStatus());

        return jdbcTemplate.update(sql, params);
    }


    public int delete(Long orderId) {
        String sql = "DELETE FROM orders WHERE order_id = :orderId";

        Map<String, Object> params = new HashMap<>();
        params.put("orderId", orderId);

        return jdbcTemplate.update(sql, params);
    }

   
    private static class OrderRowMapper implements RowMapper<Order> {
        @Override
        public Order mapRow(ResultSet rs, int rowNum) throws SQLException {
            Order order = new Order();
            order.setOrderId(rs.getLong("order_id"));
            order.setQuantity(rs.getInt("quantity"));
            order.setShippingAddressId(rs.getLong("shipping_address_id"));
            order.setOrderDate(rs.getTimestamp("order_date").toLocalDateTime());
            order.setStatus(rs.getString("status"));
            return order;
        }
    }
}
