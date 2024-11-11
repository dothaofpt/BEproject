package org.example.productservice.serviceProduct.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.util.List;

public class CategoryDTO {
    private Integer id;
    private String name;
    @JsonIgnore
    private List<ProductDTO> products;

    public CategoryDTO() {
    }

    public CategoryDTO(Integer id, String name, List<ProductDTO> products) {
        this.id = id;
        this.name = name;
        this.products = products;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<ProductDTO> getProducts() {
        return products;
    }

    public void setProducts(List<ProductDTO> products) {
        this.products = products;
    }
}

