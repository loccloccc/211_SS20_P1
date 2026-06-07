package org.example.bai1.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.bai1.dto.AuthResponse;
import org.example.bai1.dto.LoginRequest;
import org.example.bai1.dto.RefreshRequest;
import org.example.bai1.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * POST /api/auth/login
     * Đăng nhập, trả về Access Token và Refresh Token.
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    /**
     * POST /api/auth/refresh
     * Dùng Refresh Token để lấy Access Token mới.
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        return ResponseEntity.ok(authService.refresh(request.getRefreshToken()));
    }

    /**
     * POST /api/auth/logout
     * Đăng xuất – thu hồi toàn bộ token còn hiệu lực.
     * Access Token được đọc từ header Authorization.
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader("Authorization") String authHeader) {
        String accessToken = authHeader.substring(7); // bỏ "Bearer "
        authService.logout(accessToken);
        return ResponseEntity.noContent().build();
    }
}
