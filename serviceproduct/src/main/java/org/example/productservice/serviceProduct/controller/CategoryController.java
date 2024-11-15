package org.example.productservice.serviceProduct.controller;

import org.example.productservice.serviceProduct.dto.CategoryDTO;
import org.example.productservice.serviceProduct.service.CategoryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/categories")
public class CategoryController {

    @Autowired
    private CategoryService categoryService;

    // Tạo mới danh mục
    @PostMapping
    public ResponseEntity<String> createCategory(@RequestHeader("username") String username, @RequestBody CategoryDTO categoryDTO) {
        int result = categoryService.createCategory(categoryDTO);
        if (result == 1) {
            return ResponseEntity.status(HttpStatus.CREATED).body("Category created successfully by " + username);
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Category creation failed");
        }
    }

    // Lấy tất cả danh mục
    @GetMapping
    public List<CategoryDTO> getAllCategories() {
        return categoryService.getAllCategories();
    }

    // Lấy danh mục theo id
    @GetMapping("/{id}")
    public ResponseEntity<CategoryDTO> getCategoryById(@PathVariable Integer id) {
        CategoryDTO category = categoryService.getCategoryById(id);
        if (category != null) {
            return ResponseEntity.ok(category);
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
        }
    }

    // Cập nhật danh mục
    @PutMapping("/{id}")
    public ResponseEntity<String> updateCategory(@RequestHeader("username") String username, @PathVariable Integer id, @RequestBody CategoryDTO categoryDTO) {
        int result = categoryService.updateCategory(id, categoryDTO);
        if (result == 1) {
            return ResponseEntity.ok("Category updated successfully by " + username);
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Category update failed");
        }
    }

    // Xóa danh mục
    @DeleteMapping("/{id}")
    public ResponseEntity<String> deleteCategory(@RequestHeader("username") String username, @PathVariable Integer id) {
        int result = categoryService.deleteCategory(id);
        if (result == 1) {
            return ResponseEntity.ok("Category deleted successfully by " + username);
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Category deletion failed");
        }
    }
}
