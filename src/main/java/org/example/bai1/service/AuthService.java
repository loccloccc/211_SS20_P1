package org.example.bai1.service;

import lombok.RequiredArgsConstructor;
import org.example.bai1.dto.AuthResponse;
import org.example.bai1.dto.LoginRequest;
import org.example.bai1.entity.Employee;
import org.example.bai1.entity.Token;
import org.example.bai1.entity.TokenType;
import org.example.bai1.repository.EmployeeRepository;
import org.example.bai1.repository.TokenRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final EmployeeRepository employeeRepository;
    private final TokenRepository    tokenRepository;
    private final JwtService         jwtService;
    private final AuthenticationManager authenticationManager;

    // ------------------------------------------------------------------ //
    //  4.1 Đăng nhập & Cấp phát Token
    // ------------------------------------------------------------------ //

    @Transactional
    public AuthResponse login(LoginRequest request) {
        // Xác thực thông tin đăng nhập qua AuthenticationManager
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        Employee employee = employeeRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("Employee not found"));

        String accessToken  = jwtService.generateAccessToken(employee);
        String refreshToken = jwtService.generateRefreshToken(employee);

        // Thu hồi tất cả token cũ còn hiệu lực trước khi lưu token mới
        revokeAllValidTokens(employee);

        // Lưu cả Access Token và Refresh Token vào DB
        saveToken(employee, accessToken,  TokenType.ACCESS);
        saveToken(employee, refreshToken, TokenType.REFRESH);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    // ------------------------------------------------------------------ //
    //  4.3 Duy trì Phiên làm việc – Refresh Token
    // ------------------------------------------------------------------ //

    @Transactional
    public AuthResponse refresh(String refreshTokenValue) {
        // Kiểm tra tồn tại và trạng thái trong DB
        Token storedToken = tokenRepository.findByTokenValue(refreshTokenValue)
                .orElseThrow(() -> new RuntimeException("Refresh token not found"));

        if (storedToken.isRevoked() || storedToken.isExpired()) {
            throw new RuntimeException("Refresh token is revoked or expired");
        }

        // Kiểm tra thêm chữ ký và hạn dùng của chuỗi JWT
        String username = jwtService.extractUsername(refreshTokenValue);
        Employee employee = employeeRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Employee not found"));

        if (jwtService.isTokenExpired(refreshTokenValue)) {
            // Đánh dấu token hết hạn trong DB
            storedToken.setExpired(true);
            tokenRepository.save(storedToken);
            throw new RuntimeException("Refresh token JWT has expired");
        }

        // Cấp Access Token mới
        String newAccessToken = jwtService.generateAccessToken(employee);

        // Thu hồi Access Token cũ; giữ Refresh Token hiện tại
        revokeAllValidAccessTokens(employee);
        saveToken(employee, newAccessToken, TokenType.ACCESS);

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(refreshTokenValue)
                .build();
    }

    // ------------------------------------------------------------------ //
    //  4.4 Đăng xuất & Thu hồi Token
    // ------------------------------------------------------------------ //

    @Transactional
    public void logout(String accessTokenValue) {
        Token storedToken = tokenRepository.findByTokenValue(accessTokenValue)
                .orElseThrow(() -> new RuntimeException("Token not found"));

        Employee employee = storedToken.getEmployee();

        // Stream API: cập nhật toàn bộ token còn hiệu lực → revoked = true, expired = true
        List<Token> validTokens = tokenRepository.findAllValidTokensByEmployee(employee.getId());

        List<Token> updatedTokens = validTokens.stream()
                .map(token -> {
                    token.setRevoked(true);
                    token.setExpired(true);
                    return token;
                })
                .collect(Collectors.toList());

        tokenRepository.saveAll(updatedTokens);

        // Dọn dẹp Security Context
        SecurityContextHolder.clearContext();
    }

    // ------------------------------------------------------------------ //
    //  Helper methods
    // ------------------------------------------------------------------ //

    private void saveToken(Employee employee, String tokenValue, TokenType type) {
        Token token = Token.builder()
                .tokenValue(tokenValue)
                .tokenType(type)
                .revoked(false)
                .expired(false)
                .employee(employee)
                .build();
        tokenRepository.save(token);
    }

    /**
     * Thu hồi tất cả token còn hiệu lực (cả ACCESS và REFRESH) của nhân viên.
     * Dùng Stream API để biến đổi danh sách.
     */
    private void revokeAllValidTokens(Employee employee) {
        List<Token> validTokens = tokenRepository.findAllValidTokensByEmployee(employee.getId());

        if (validTokens.isEmpty()) return;

        List<Token> revoked = validTokens.stream()
                .map(t -> { t.setRevoked(true); t.setExpired(true); return t; })
                .collect(Collectors.toList());

        tokenRepository.saveAll(revoked);
    }

    /**
     * Chỉ thu hồi Access Token còn hiệu lực – giữ nguyên Refresh Token khi refresh.
     */
    private void revokeAllValidAccessTokens(Employee employee) {
        List<Token> validTokens = tokenRepository.findAllValidTokensByEmployee(employee.getId());

        if (validTokens.isEmpty()) return;

        List<Token> revoked = validTokens.stream()
                .filter(t -> t.getTokenType() == TokenType.ACCESS)
                .map(t -> { t.setRevoked(true); t.setExpired(true); return t; })
                .collect(Collectors.toList());

        tokenRepository.saveAll(revoked);
    }
}
