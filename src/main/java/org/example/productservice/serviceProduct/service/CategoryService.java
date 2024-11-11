package org.example.productservice.serviceProduct.service;

import org.example.productservice.serviceProduct.dto.CategoryDTO;

import java.util.List;

public interface CategoryService {
    int createCategory(CategoryDTO categoryDTO);

    List<CategoryDTO> getAllCategories();

    CategoryDTO getCategoryById(Integer id);

    int updateCategory(Integer id, CategoryDTO categoryDTO);

    int deleteCategory(Integer id);
}

