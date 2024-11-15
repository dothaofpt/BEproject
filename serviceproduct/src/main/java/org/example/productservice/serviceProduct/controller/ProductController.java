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
@RequestMapping("/products")
public class ProductController {

    @Autowired
    private ProductService productService;

    // Tạo sản phẩm mới
    @PostMapping
    public ResponseEntity<Map<String, String>> createProduct(
            @RequestHeader("username") String username,
            @RequestBody ProductDTO productDTO) {

        System.out.println("Username from header: " + username);
        Map<String, String> response = new HashMap<>();

        // Kiểm tra xem CategoryId có null không
        if (productDTO.getCategoryId() == null) {
            response.put("error", "Category ID cannot be null");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }

        try {
            // Tạo sản phẩm mới
            int result = productService.createProduct(productDTO);

            // Kiểm tra kết quả và trả về phản hồi phù hợp
            if (result == 1) {
                response.put("message", "Product created successfully by " + username);
                return ResponseEntity.status(HttpStatus.CREATED).body(response);
            } else {
                response.put("message", "Product creation failed");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
            }

        } catch (IllegalArgumentException e) {
            // Xử lý lỗi và trả về thông báo lỗi
            response.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }

    // Lấy danh sách sản phẩm theo category_id
    @GetMapping("/{categoryId}")
    public ResponseEntity<List<ProductDTO>> getProductsByCategoryId(@RequestHeader("username") String username, @PathVariable Integer categoryId) {
        try {
            List<ProductDTO> products = productService.getProductsByCategoryId(categoryId);
            return ResponseEntity.ok(products);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        }
    }

    // Cập nhật sản phẩm
    @PutMapping("/{id}")
    public ResponseEntity<Map<String, String>> updateProduct(@RequestHeader("username") String username, @PathVariable Integer id, @RequestBody ProductDTO productDTO) {
        try {
            int result = productService.updateProduct(id, productDTO);
            Map<String, String> response = new HashMap<>();
            if (result == 1) {
                response.put("message", "Product updated successfully by " + username);
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
    public ResponseEntity<Map<String, String>> deleteProduct(@RequestHeader("username") String username, @PathVariable Integer id) {
        try {
            int result = productService.deleteProduct(id);
            Map<String, String> response = new HashMap<>();
            if (result == 1) {
                response.put("message", "Product deleted successfully by " + username);
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
    public ResponseEntity<ProductDTO> getProductById(@RequestHeader("username") String username, @PathVariable Integer id) {
        ProductDTO product = productService.getProductById(id);
        if (product != null) {
            return ResponseEntity.ok(product);
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
        }
    }
}
