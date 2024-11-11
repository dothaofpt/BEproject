package org.example.productservice.serviceProduct.service;

import org.example.productservice.serviceProduct.dto.ProductDTO;

import java.util.List;

public interface ProductService {
    int createProduct(ProductDTO productDTO);

    List<ProductDTO> getProductsByCategoryId(Integer categoryId);

    ProductDTO getProductById(Integer id);

    int updateProduct(Integer id, ProductDTO productDTO);

    int deleteProduct(Integer id);
}
