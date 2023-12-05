package com.example.security_jwt.Auth;

import com.example.security_jwt.config.JwtService;
import com.example.security_jwt.User.Role;
import com.example.security_jwt.User.User;
import com.example.security_jwt.User.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    public AuthenticationRespond register(RegisterRequest request) {
        var user = User.builder()
                .username(request.getUsername())
                .name(request.getName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        userRepository.save(user);
        var jwt = jwtService.generateToken(user);
        return AuthenticationRespond.builder()
                .token(jwt)
                .build();
    }

    public AuthenticationRespond authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );
        var user = userRepository.findByUsername(request.getUsername())
                .orElseThrow();
        var jwt = jwtService.generateToken(user);
        return AuthenticationRespond.builder()
                .token(jwt)
                .build();
    }
    public List<User> showalldata(){
        return userRepository.findAll();
    }

    public AuthenticationRespond update(Integer id,UpdateRequest request) {
        Optional<User> optionalUser = userRepository.findById(id);
        User user = null;
        if (optionalUser.isPresent()) {
            user = optionalUser.get();
            user.setUsername(request.getUsername());
            user.setName(request.getName());
            user.setEmail(request.getEmail());
            user.setPassword(passwordEncoder.encode(request.getPassword()));
            userRepository.save(user);
        }
        String jwt = jwtService.generateToken(user);
        return AuthenticationRespond.builder()
                .token(jwt)
                .build();
    }

    public String delete(Integer id){
        Optional<User> optionalUser = userRepository.findById(id);
        if(optionalUser.isPresent()){
            userRepository.delete(optionalUser.get());
            return "User deleted successfully";
        }else {
            return "User deleted User not found";
        }
    }
}
