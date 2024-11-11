package org.example.productservice.serviceProduct.controller;

import org.example.productservice.serviceProduct.dto.ProductDTO;
import org.example.productservice.serviceProduct.service.ProductService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/products")
public class ProductController {

    @Autowired
    private ProductService productService;

    // Tạo sản phẩm mới
    @PostMapping
    public ResponseEntity<Map<String, String>> createProduct(@RequestBody ProductDTO productDTO) {
        Map<String, String> response = new HashMap<>();
        try {
            // Kiểm tra nếu categoryId là null
            if (productDTO.getCategoryId() == null) {
                response.put("error", "Category ID cannot be null");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
            }

            int result = productService.createProduct(productDTO);
            if (result == 1) {
                response.put("message", "Product created successfully");
                return ResponseEntity.status(HttpStatus.CREATED).body(response);
            } else {
                response.put("message", "Product creation failed");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
            }
        } catch (IllegalArgumentException e) {
            response.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }


    // Lấy danh sách sản phẩm theo category_id
    @GetMapping("/{categoryId}")
    public ResponseEntity<List<ProductDTO>> getProductsByCategoryId(@PathVariable Integer categoryId) {
        try {
            List<ProductDTO> products = productService.getProductsByCategoryId(categoryId);
            return ResponseEntity.ok(products);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        }
    }

    // Cập nhật sản phẩm
    @PutMapping("/{id}")
    public ResponseEntity<Map<String, String>> updateProduct(@PathVariable Integer id, @RequestBody ProductDTO productDTO) {
        try {
            int result = productService.updateProduct(id, productDTO);
            Map<String, String> response = new HashMap<>();
            if (result == 1) {
                response.put("message", "Product updated successfully");
                return ResponseEntity.ok(response);
            } else {
                response.put("message", "Product update failed");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
            }
        } catch (IllegalArgumentException e) {
            Map<String, String> response = new HashMap<>();
            response.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }

    // Xóa sản phẩm
    @DeleteMapping("/{id}")
    public ResponseEntity<Map<String, String>> deleteProduct(@PathVariable Integer id) {
        try {
            int result = productService.deleteProduct(id);
            Map<String, String> response = new HashMap<>();
            if (result == 1) {
                response.put("message", "Product deleted successfully");
                return ResponseEntity.ok(response);
            } else {
                response.put("message", "Product deletion failed");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
            }
        } catch (IllegalArgumentException e) {
            Map<String, String> response = new HashMap<>();
            response.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }

    // Lấy sản phẩm theo id
    @GetMapping("/product/{id}")
    public ResponseEntity<ProductDTO> getProductById(@PathVariable Integer id) {
        ProductDTO product = productService.getProductById(id);
        if (product != null) {
            return ResponseEntity.ok(product);
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
        }
    }
}

