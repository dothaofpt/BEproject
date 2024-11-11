package org.example.serviceuser.userService.repository;

import org.example.serviceuser.userService.entity.Address;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface AddressRepository extends JpaRepository<Address, Long> {
    List<Address> findByUser_UserId(Long userId); // Sử dụng userId nếu thuộc tính trong User là userId
}
