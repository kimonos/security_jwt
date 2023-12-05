package com.example.security_jwt.User;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;


//繼承JpaRepository介面，使UserRepository有基本的CRUD功能，User為對應的實體類，Integer為主鍵類別
public interface UserRepository extends JpaRepository<User,Integer> {

    Optional<User> findByUsername(String username);//Optional能夠減少例外處理，進行query返回與名稱相同的user
}
