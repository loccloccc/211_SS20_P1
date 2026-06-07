package org.example.bai1.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.bai1.entity.Employee;
import org.example.bai1.entity.Role;
import org.example.bai1.repository.EmployeeRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.stream.Collectors;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class DataInitializer {

    private final EmployeeRepository employeeRepository;
    private final PasswordEncoder    passwordEncoder;

    @Bean
    public CommandLineRunner seedDatabase() {
        return args -> {
            if (employeeRepository.count() > 0) {
                log.info("Database already seeded. Skipping initialization.");
                return;
            }

            // Hardcode dữ liệu mẫu
            List<Employee> sampleEmployees = List.of(
                Employee.builder()
                    .username("admin")
                    .password(passwordEncoder.encode("admin123"))
                    .role(Role.ADMIN)
                    .active(true)
                    .build(),
                Employee.builder()
                    .username("employee1")
                    .password(passwordEncoder.encode("emp123"))
                    .role(Role.USER)
                    .active(true)
                    .build(),
                Employee.builder()
                    .username("employee2")
                    .password(passwordEncoder.encode("emp456"))
                    .role(Role.USER)
                    .active(false)  // inactive – demo
                    .build()
            );

            // Stream API: log tên tài khoản được tạo
            List<Employee> saved = employeeRepository.saveAll(sampleEmployees);
            String names = saved.stream()
                    .map(Employee::getUsername)
                    .collect(Collectors.joining(", "));

            log.info("Seeded {} employees: [{}]", saved.size(), names);
        };
    }
}
