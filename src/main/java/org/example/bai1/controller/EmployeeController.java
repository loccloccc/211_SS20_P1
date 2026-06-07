package org.example.bai1.controller;

import lombok.RequiredArgsConstructor;
import org.example.bai1.entity.Employee;
import org.example.bai1.repository.EmployeeRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/employees")
@RequiredArgsConstructor
public class EmployeeController {

    private final EmployeeRepository employeeRepository;

    /**
     * GET /api/employees
     * Chỉ ADMIN mới được truy cập.
     * Stream API: lọc danh sách nhân viên đang hoạt động.
     */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<String>> getActiveEmployees() {
        List<String> activeUsernames = employeeRepository.findAll().stream()
                .filter(Employee::isActive)
                .map(Employee::getUsername)
                .collect(Collectors.toList());

        return ResponseEntity.ok(activeUsernames);
    }

    /**
     * GET /api/employees/me
     * Mọi user đã xác thực đều truy cập được thông tin cá nhân.
     */
    @GetMapping("/me")
    public ResponseEntity<String> getCurrentEmployee(
            @AuthenticationPrincipal Employee employee) {
        return ResponseEntity.ok("Logged in as: " + employee.getUsername() + " | Role: " + employee.getRole());
    }
}
