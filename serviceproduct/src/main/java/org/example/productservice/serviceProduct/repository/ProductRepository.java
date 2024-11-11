package org.example.productservice.serviceProduct.repository;

import org.example.productservice.serviceProduct.dto.ProductDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public class ProductRepository {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    public int createProduct(ProductDTO productDTO) {
        String sql = "INSERT INTO products (name, price, thumbnail, description, category_id) VALUES (?, ?, ?, ?, ?)";
        return jdbcTemplate.update(sql, productDTO.getName(), productDTO.getPrice(), productDTO.getThumbnail(),
                productDTO.getDescription(), productDTO.getCategoryId());
    }

    public List<ProductDTO> getProductsByCategoryId(Integer categoryId) {
        String sql = "SELECT * FROM products WHERE category_id = ?";
        return jdbcTemplate.query(sql, new Object[]{categoryId}, (rs, rowNum) -> new ProductDTO(
                rs.getInt("id"),
                rs.getString("name"),
                rs.getFloat("price"),
                rs.getString("thumbnail"),
                rs.getString("description"),
                rs.getObject("created_at", LocalDateTime.class),
                rs.getObject("updated_at", LocalDateTime.class),
                categoryId
        ));
    }

    public int updateProduct(Integer id, ProductDTO productDTO) {
        String sql = "UPDATE products SET name = ?, price = ?, thumbnail = ?, description = ?, category_id = ? WHERE id = ?";
        return jdbcTemplate.update(sql, productDTO.getName(), productDTO.getPrice(), productDTO.getThumbnail(),
                productDTO.getDescription(), productDTO.getCategoryId(), id);
    }

    public int deleteProduct(Integer id) {
        String sql = "DELETE FROM products WHERE id = ?";
        return jdbcTemplate.update(sql, id);
    }

    public ProductDTO getProductById(Integer id) {
        String sql = "SELECT * FROM products WHERE id = ?";
        return jdbcTemplate.queryForObject(sql, new Object[]{id}, (rs, rowNum) -> new ProductDTO(
                rs.getInt("id"),
                rs.getString("name"),
                rs.getFloat("price"),
                rs.getString("thumbnail"),
                rs.getString("description"),
                rs.getObject("created_at", LocalDateTime.class),
                rs.getObject("updated_at", LocalDateTime.class),
                rs.getInt("category_id")
        ));
    }
}

