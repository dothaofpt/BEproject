package org.example.productservice.serviceProduct.service;

import org.example.productservice.serviceProduct.dto.CategoryDTO;
import org.example.productservice.serviceProduct.repository.CategoryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CategoryServiceImpl implements CategoryService {

    @Autowired
    private CategoryRepository categoryRepository;

    @Override
    public int createCategory(CategoryDTO categoryDTO) {
        return categoryRepository.createCategory(categoryDTO);
    }

    @Override
    public List<CategoryDTO> getAllCategories() {
        return categoryRepository.getAllCategories();
    }

    @Override
    public CategoryDTO getCategoryById(Integer id) {
        return categoryRepository.getCategoryById(id);
    }

    @Override
    public int updateCategory(Integer id, CategoryDTO categoryDTO) {
        return categoryRepository.updateCategory(id, categoryDTO);
    }

    @Override
    public int deleteCategory(Integer id) {
        return categoryRepository.deleteCategory(id);
    }
}

