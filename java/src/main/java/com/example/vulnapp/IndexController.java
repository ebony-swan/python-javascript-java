package com.example.vulnapp;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.TreeSet;
import java.util.Set;
import java.util.stream.Collectors;

/** Renders an index of every registered endpoint for easy navigation. */
@RestController
public class IndexController {

    private final RequestMappingHandlerMapping mapping;

    public IndexController(RequestMappingHandlerMapping mapping) {
        this.mapping = mapping;
    }

    @GetMapping(value = "/", produces = "text/html")
    public String index() {
        List<String[]> rows = new ArrayList<>();
        for (RequestMappingInfo info : mapping.getHandlerMethods().keySet()) {
            Set<String> patterns = new TreeSet<>();
            if (info.getPathPatternsCondition() != null) {
                info.getPathPatternsCondition().getPatterns()
                        .forEach(p -> patterns.add(p.getPatternString()));
            } else if (info.getPatternsCondition() != null) {
                patterns.addAll(info.getPatternsCondition().getPatterns());
            }
            String methods = info.getMethodsCondition().getMethods().isEmpty()
                    ? "GET"
                    : info.getMethodsCondition().getMethods().stream()
                        .map(Enum::name).sorted().collect(Collectors.joining(", "));
            for (String p : patterns) {
                if (p.equals("/") || p.startsWith("/error")) {
                    continue;
                }
                rows.add(new String[] {methods, p});
            }
        }
        rows.sort(Comparator.comparing(r -> r[1]));

        StringBuilder tbody = new StringBuilder();
        for (String[] r : rows) {
            tbody.append("<tr><td>").append(r[0]).append("</td><td><code>")
                 .append(r[1]).append("</code></td></tr>");
        }
        return "<!doctype html><html><head><meta charset=\"utf-8\">"
             + "<title>Java VulnApp — endpoint index</title><style>"
             + "body{font-family:system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem}"
             + "td,th{border:1px solid #ddd;padding:.4rem .6rem;text-align:left}"
             + "table{border-collapse:collapse;width:100%}"
             + "code{background:#f4f4f4;padding:.1rem .3rem;border-radius:3px}"
             + ".warn{background:#fff3cd;border:1px solid #ffe69c;padding:.6rem 1rem;border-radius:6px}"
             + "</style></head><body>"
             + "<p class=\"warn\">⚠️ Intentionally vulnerable demo app — for security education only.</p>"
             + "<h1>Java VulnApp</h1>"
             + "<p>Deliberately vulnerable Spring Boot app demonstrating OWASP Top 10 "
             + "code-level issues with multiple permutations per category.</p>"
             + "<table><thead><tr><th>Methods</th><th>Path</th></tr></thead><tbody>"
             + tbody + "</tbody></table></body></html>";
    }
}
