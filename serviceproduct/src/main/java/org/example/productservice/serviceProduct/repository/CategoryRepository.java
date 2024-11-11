package org.example.productservice.serviceProduct.repository;

import org.example.productservice.serviceProduct.dto.CategoryDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class CategoryRepository {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    public int createCategory(CategoryDTO categoryDTO) {
        String sql = "INSERT INTO categories (name) VALUES (?)";
        return jdbcTemplate.update(sql, categoryDTO.getName());
    }

    public List<CategoryDTO> getAllCategories() {
        String sql = "SELECT * FROM categories";
        return jdbcTemplate.query(sql, (rs, rowNum) -> new CategoryDTO(
                rs.getInt("id"),
                rs.getString("name"),
                null
        ));
    }

    public CategoryDTO getCategoryById(Integer id) {
        String sql = "SELECT * FROM categories WHERE id = ?";
        return jdbcTemplate.queryForObject(sql, new Object[]{id}, (rs, rowNum) -> new CategoryDTO(
                rs.getInt("id"),
                rs.getString("name"),
                null
        ));
    }

    public int updateCategory(Integer id, CategoryDTO categoryDTO) {
        String sql = "UPDATE categories SET name = ? WHERE id = ?";
        return jdbcTemplate.update(sql, categoryDTO.getName(), id);
    }

    public int deleteCategory(Integer id) {
        String sql = "DELETE FROM categories WHERE id = ?";
        return jdbcTemplate.update(sql, id);
    }
}

