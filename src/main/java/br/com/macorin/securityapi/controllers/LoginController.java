package br.com.macorin.securityapi.controllers;

import br.com.macorin.securityapi.models.LoginRequest;
import br.com.macorin.securityapi.models.LoginResponse;
import br.com.macorin.securityapi.services.LoginService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class LoginController {

    private LoginService loginService;

    public LoginController(LoginService loginService) {
        this.loginService = loginService;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest) {
        return loginService.login(loginRequest);
    }
}
