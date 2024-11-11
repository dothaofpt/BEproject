package org.example.productservice.serviceProduct.service;

import org.example.productservice.serviceProduct.dto.ProductDTO;
import org.example.productservice.serviceProduct.repository.ProductRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ProductServiceImpl implements ProductService {

    @Autowired
    private ProductRepository productRepository;

    @Override
    public int createProduct(ProductDTO productDTO) {
        if (productDTO.getCategoryId() != 1 && productDTO.getCategoryId() != 2) {
            throw new IllegalArgumentException("Invalid category_id. It must be either 1 or 2.");
        }
        return productRepository.createProduct(productDTO);
    }

    @Override
    public List<ProductDTO> getProductsByCategoryId(Integer categoryId) {
        if (categoryId != 1 && categoryId != 2) {
            throw new IllegalArgumentException("Invalid category_id. It must be either 1 or 2.");
        }
        return productRepository.getProductsByCategoryId(categoryId);
    }

    @Override
    public ProductDTO getProductById(Integer id) {
        return productRepository.getProductById(id);
    }

    @Override
    public int updateProduct(Integer id, ProductDTO productDTO) {
        if (productDTO.getCategoryId() != 1 && productDTO.getCategoryId() != 2) {
            throw new IllegalArgumentException("Invalid category_id. It must be either 1 or 2.");
        }
        return productRepository.updateProduct(id, productDTO);
    }

    @Override
    public int deleteProduct(Integer id) {
        return productRepository.deleteProduct(id);
    }
}

