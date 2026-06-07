package org.example.bai1.repository;

import org.example.bai1.entity.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<Token, Long> {

    /**
     * Tìm tất cả token còn hiệu lực (chưa hết hạn và chưa bị thu hồi) của một nhân viên.
     */
    @Query("""
            SELECT t FROM Token t
            WHERE t.employee.id = :employeeId
              AND t.revoked = false
              AND t.expired = false
            """)
    List<Token> findAllValidTokensByEmployee(@Param("employeeId") Long employeeId);

    Optional<Token> findByTokenValue(String tokenValue);
}
