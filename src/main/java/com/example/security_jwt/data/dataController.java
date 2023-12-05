package com.example.security_jwt.data;

import com.example.security_jwt.Auth.AuthenticationRespond;
import com.example.security_jwt.Auth.AuthenticationService;
import com.example.security_jwt.Auth.UpdateRequest;
import com.example.security_jwt.User.User;
import com.example.security_jwt.User.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/data")
public class dataController {
    @Autowired
    UserRepository userRepository;
    @Autowired
    AuthenticationService service;


    @GetMapping("/allData")
    public ResponseEntity<List<User>> show(){
        return ResponseEntity.ok(userRepository.findAll());
    }

    @PostMapping("/update/{id}")
    public ResponseEntity<AuthenticationRespond> update(@PathVariable Integer id, @RequestBody UpdateRequest request){
        return ResponseEntity.ok(service.update(id,request));
    }

    @DeleteMapping("/delete/{id}")
    public ResponseEntity<String> delete(@PathVariable Integer id){
        return ResponseEntity.ok(service.delete(id));
    }
}
