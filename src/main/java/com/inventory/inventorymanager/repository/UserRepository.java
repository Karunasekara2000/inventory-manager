package com.inventory.inventorymanager.repository;

import com.inventory.inventorymanager.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Integer> {

    Optional<User> findByEmailAndPassword(String email,String password);
    Optional<User> findByEmail(String email);
}
