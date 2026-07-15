using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System.Diagnostics;
using System.IO;
using System.Xml.Serialization;
using YamlDotNet.Serialization;

namespace VulnApp.Controllers;

/// <summary>
/// Insecure Deserialization / Software &amp; Data Integrity Failures —
/// OWASP 2021 A08 | OWASP 2025 A08.
///
/// Mirrors the annotation format and attribute-routed action style of
/// SqlInjectionController. Each handler feeds an UNTRUSTED request body to a real
/// deserializer sink (Newtonsoft $type, YamlDotNet, XmlSerializer) so the flaw is
/// genuinely exercised — no stubs — when the app runs.
///
/// NOTE ON GADGETS: the historic .NET RCE gadgets (WPF ObjectDataProvider, the
/// TypeConfuseDelegate chain, …) live in assemblies a minimal ASP.NET Core web
/// image never loads, and BinaryFormatter is removed in .NET 9. To keep the RCE
/// DETERMINISTIC on this image, the app ships its own reachable gadget type
/// (DeserCommandGadget / DeserYamlConfig) whose property SETTER shells out —
/// which is exactly how real, application-specific gadget chains behave. The
/// genuine, real-world bug is the SINK: handing attacker-controlled JSON/YAML/XML
/// to a polymorphic / type-resolving deserializer that then instantiates
/// attacker-chosen types and runs their setters.
/// </summary>
[ApiController]
public class DeserializationController : ControllerBase
{
    // ========================================================================
    // PERMUTATION 1 — Newtonsoft.Json TypeNameHandling.All ($type gadget)
    // OWASP 2021 A08 Software and Data Integrity Failures -> OWASP 2025 A08 Software and Data Integrity Failures
    // CWE-502: Deserialization of Untrusted Data
    // EXPLOITATION LIKELIHOOD: HIGH — pre-auth POST, no tooling; the attacker's
    //   JSON "$type" picks the CLR type Json.NET instantiates, and its setters run
    //   during load. Deterministic RCE the moment ANY side-effecting gadget type
    //   is loadable (this app ships one); the classic .NET deserialization sink.
    // PREVALENCE TODAY: greenfield LOW (Json.NET defaults to TypeNameHandling.None
    //   and System.Text.Json has no type-embedding mode; SAST flags TypeNameHandling)
    //   | legacy/10yr tech-debt HIGH (TypeNameHandling.Auto/All was copy-pasted from
    //   old tutorials into WCF replacements, SignalR hubs and cache/config serializers).
    // EXAMPLE: curl -X POST http://127.0.0.1:5001/deserialization/native \
    //   -H 'Content-Type: application/json' \
    //   --data '{"$type":"VulnApp.Controllers.DeserCommandGadget, VulnApp","Cmd":"id"}'
    //   -> Json.NET builds DeserCommandGadget and its Cmd setter runs `id`.
    // FIX: never enable TypeNameHandling on untrusted input; bind to a fixed DTO
    //   with System.Text.Json (see /deserialization/native-safe).
    // ========================================================================
    [HttpPost("/deserialization/native")]
    public async Task<IActionResult> Native()
    {
        var body = await ReadBodyAsync();
        // VULNERABLE: TypeNameHandling.All honours the attacker's "$type", so the
        // request body chooses which CLR type is instantiated (and setters fired).
        var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
        try
        {
            var obj = JsonConvert.DeserializeObject(body, settings);
            return new JsonResult(new
            {
                sink = "JsonConvert.DeserializeObject(body, TypeNameHandling.All)",
                input = body,
                resolvedType = obj?.GetType().FullName,
                gadget = obj is DeserCommandGadget g ? (object)new { g.Cmd, g.Output } : null,
                note = "$type instantiates ANY loadable type; the shipped gadget's setter shelled out"
            });
        }
        catch (Exception e)
        {
            return new JsonResult(new { input = body, error = e.Message }) { StatusCode = 500 };
        }
    }

    // ========================================================================
    // PERMUTATION 2 — YamlDotNet deserialization into a side-effecting config type
    // OWASP 2021 A08 Software and Data Integrity Failures -> OWASP 2025 A08 Software and Data Integrity Failures
    // CWE-502: Deserialization of Untrusted Data
    // EXPLOITATION LIKELIHOOD: MEDIUM — untrusted YAML is deserialized into a rich
    //   "config" object whose property setter runs a command. Deterministic here,
    //   but rated MEDIUM honestly: unlike SnakeYAML/PyYAML, YamlDotNet does NOT
    //   auto-instantiate arbitrary "!clr" tag types, so the exploit needs the app
    //   to map untrusted YAML onto a type that already does something dangerous.
    // PREVALENCE TODAY: greenfield LOW (YamlDotNet is safe-by-default; configs are
    //   parsed into inert typed DTOs and rarely come from users) | legacy/10yr
    //   tech-debt MEDIUM (config-as-code pipelines deserialize user/CI-supplied
    //   YAML straight into feature-rich domain objects).
    // EXAMPLE: curl -X POST http://127.0.0.1:5001/deserialization/yaml \
    //   --data $'Command: id\n'   -> the Command setter runs `id`.
    // FIX: deserialize into an INERT DTO (plain data, no side-effecting setters)
    //   and never act on values a setter received from untrusted YAML.
    // ========================================================================
    [HttpPost("/deserialization/yaml")]
    public async Task<IActionResult> Yaml()
    {
        var body = await ReadBodyAsync();
        var deserializer = new DeserializerBuilder().Build();
        try
        {
            // VULNERABLE: untrusted YAML deserialized into a rich type whose Command
            // property setter has an OS-command side effect.
            var cfg = deserializer.Deserialize<DeserYamlConfig>(body);
            return new JsonResult(new
            {
                sink = "YamlDotNet Deserializer.Deserialize<DeserYamlConfig>(body)",
                input = body,
                command = cfg?.Command,
                output = cfg?.Output,
                note = "YamlDotNet won't build arbitrary !clr tag types like SnakeYAML, but mapping untrusted YAML onto side-effecting types is still CWE-502"
            });
        }
        catch (Exception e)
        {
            return new JsonResult(new { input = body, error = e.Message }) { StatusCode = 500 };
        }
    }

    // ========================================================================
    // PERMUTATION 3 — XmlSerializer whose TARGET TYPE is resolved from the request
    // OWASP 2021 A08 Software and Data Integrity Failures -> OWASP 2025 A08 Software and Data Integrity Failures
    // CWE-502: Deserialization of Untrusted Data
    // EXPLOITATION LIKELIHOOD: MEDIUM — the caller supplies BOTH the type name and
    //   the XML, so an XmlSerializer is built for an attacker-chosen type and fed
    //   attacker XML, instantiating it and running its setters. Deterministic given
    //   a reachable gadget (shipped); rated MEDIUM because it needs the app to take
    //   the serializer type from the request and XmlSerializer lacks the universal
    //   RCE gadgets BinaryFormatter had.
    // PREVALENCE TODAY: greenfield LOW (XML is bound to a FIXED DTO; resolving
    //   Type.GetType() from request input is an obvious review/SAST smell) |
    //   legacy/10yr tech-debt MEDIUM (old SOAP/plugin/importer code that picks the
    //   deserialization type by name from a header, envelope field or query param).
    // EXAMPLE: curl -X POST 'http://127.0.0.1:5001/deserialization/xml?type=VulnApp.Controllers.DeserCommandGadget' \
    //   -H 'Content-Type: application/xml' \
    //   --data '<DeserCommandGadget><Cmd>id</Cmd></DeserCommandGadget>'
    //   -> XmlSerializer builds the gadget and its Cmd setter runs `id`.
    // FIX: hard-code ONE known DTO type for the serializer; never resolve it from
    //   user input, and deserialize into inert data objects.
    // ========================================================================
    [HttpPost("/deserialization/xml")]
    public async Task<IActionResult> Xml(string type = "")
    {
        var body = await ReadBodyAsync();
        try
        {
            // VULNERABLE: the deserialization target TYPE is chosen by the caller.
            var t = Type.GetType(type);
            if (t == null)
                return new JsonResult(new { requestedType = type, error = "type not found / not loadable" }) { StatusCode = 400 };

            var serializer = new XmlSerializer(t);
            using var reader = new StringReader(body);
            var obj = serializer.Deserialize(reader);
            return new JsonResult(new
            {
                sink = "new XmlSerializer(Type.GetType(userType)).Deserialize(body)",
                requestedType = type,
                resolvedType = obj?.GetType().FullName,
                gadget = obj is DeserCommandGadget g ? (object)new { g.Cmd, g.Output } : null,
                note = "resolving the serializer type from the request lets XML drive arbitrary type instantiation + setters"
            });
        }
        catch (Exception e)
        {
            return new JsonResult(new { requestedType = type, error = e.Message }) { StatusCode = 500 };
        }
    }

    // ========================================================================
    // SAFE REFERENCE — System.Text.Json bound to a FIXED, inert DTO. There is no
    // type handling and no polymorphism, so a "$type" key is treated as ordinary
    // (ignored) data: no attacker-chosen type is ever instantiated. Diff this
    // against PERMUTATION 1 for SAST tooling and learners.
    // ========================================================================
    [HttpPost("/deserialization/native-safe")]
    public async Task<IActionResult> NativeSafe()
    {
        var body = await ReadBodyAsync();
        try
        {
            // SAFE: fixed target type, default options — "$type" is inert data.
            var dto = System.Text.Json.JsonSerializer.Deserialize<SafeMessageDto>(body,
                new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            return new JsonResult(new { safe = true, parsedInto = nameof(SafeMessageDto), message = dto?.Message });
        }
        catch (Exception e)
        {
            return new JsonResult(new { safe = true, error = e.Message }) { StatusCode = 400 };
        }
    }

    // --- helpers -------------------------------------------------------------

    private async Task<string> ReadBodyAsync()
    {
        using var reader = new StreamReader(Request.Body);
        return await reader.ReadToEndAsync();
    }
}

// ============================================================================
// Shipped gadget + DTOs. Category-unique names ("Deser…") so they never collide
// with the shared VulnApp.Controllers namespace used by the other lab modules.
// ============================================================================

// A realistic application gadget: a "command/config" object whose property SETTER
// has an OS-command side effect. It is reachable by every deserializer above,
// which is what turns attacker-controlled type instantiation into RCE on this
// minimal image (where the classic library gadgets are not loaded).
public class DeserCommandGadget
{
    private string _cmd;
    public string Cmd
    {
        get => _cmd;
        set { _cmd = value; Output = DeserRce.RunShell(value); } // VULNERABLE: side-effecting setter (the gadget)
    }

    [XmlIgnore]
    public string Output { get; set; }
}

// The YAML permutation's "config" type — same side-effecting-setter shape, its own
// name/property so the /yaml payload reads like a config file with a hook.
public class DeserYamlConfig
{
    private string _command;
    public string Command
    {
        get => _command;
        set { _command = value; Output = DeserRce.RunShell(value); } // VULNERABLE: side-effecting setter (the gadget)
    }

    [YamlIgnore]
    public string Output { get; set; }
}

// Inert DTO used by the SAFE handler — plain data, no side effects.
public class SafeMessageDto
{
    public string Message { get; set; }
}

// Minimal shell-exec used by the gadget setters so the RCE is observable in the
// HTTP response (mirrors the CommandInjection module's process helper).
internal static class DeserRce
{
    public static string RunShell(string command)
    {
        if (string.IsNullOrEmpty(command)) return "";
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "/bin/sh",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                WorkingDirectory = Directory.GetCurrentDirectory(),
            };
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add(command);
            using var p = Process.Start(psi);
            var outp = p.StandardOutput.ReadToEnd();
            var errp = p.StandardError.ReadToEnd();
            p.WaitForExit(10000);
            return (outp + errp).Trim();
        }
        catch (Exception e)
        {
            return "exec error: " + e.Message;
        }
    }
}
