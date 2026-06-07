package org.example.bai1.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.example.bai1.repository.TokenRepository;
import org.example.bai1.service.JwtService;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Bộ lọc JWT – chặn mọi request và kiểm tra Access Token.
 * Ngoài việc xác minh chữ ký và thời hạn JWT, bộ lọc còn truy vấn bảng Token
 * trong CSDL để đảm bảo token chưa bị thu hồi (revoked = false).
 */
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService        jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenRepository   tokenRepository;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        // Không có Bearer token → tiếp tục chuỗi filter
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String jwt      = authHeader.substring(7);
        final String username;

        try {
            username = jwtService.extractUsername(jwt);
        } catch (Exception e) {
            // Token không parse được (sai chữ ký, định dạng sai, …)
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid JWT token");
            return;
        }

        // Chỉ xử lý tiếp nếu chưa có authentication trong SecurityContext
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // 1. Kiểm tra chữ ký + thời hạn trên chuỗi JWT
            // 2. Truy vấn CSDL: token phải tồn tại và chưa bị thu hồi
            boolean isTokenValidInDb = tokenRepository.findByTokenValue(jwt)
                    .map(t -> !t.isRevoked() && !t.isExpired())
                    .orElse(false);

            if (jwtService.isTokenValid(jwt, userDetails) && isTokenValidInDb) {
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                        );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            } else {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token is invalid or revoked");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}
