package com.example.vulnapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Deliberately-vulnerable Spring Boot demo app.
 *
 * <pre>
 *   mvn spring-boot:run          # http://127.0.0.1:8080/
 * </pre>
 *
 * Vulnerability "modules" are plain {@code @RestController} / {@code @Controller}
 * classes under {@code com.example.vulnapp.vulns}. Component scanning discovers
 * them automatically, so each OWASP category lives in its own self-contained
 * class with no central wiring to edit.
 *
 * <p>WARNING: intentional security vulnerabilities — never expose to an
 * untrusted network.
 */
@SpringBootApplication
public class VulnAppApplication {
    public static void main(String[] args) {
        SpringApplication.run(VulnAppApplication.class, args);
    }
}
