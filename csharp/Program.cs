// C# VulnApp — deliberately vulnerable ASP.NET Core app demonstrating OWASP
// Top 10 code-level issues, with multiple permutations per category.
//
//   cd csharp && dotnet run        # http://127.0.0.1:5001/
//
// Vulnerability modules are attribute-routed controllers under Controllers/ and
// are discovered automatically by MapControllers — no central wiring to edit.
//
// WARNING: intentional security vulnerabilities — never expose to an untrusted
// network.
using Microsoft.AspNetCore.Routing;
using System.Text;
using VulnApp;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();

var app = builder.Build();

Db.Init();
app.MapControllers();

app.MapGet("/", (EndpointDataSource eds) =>
{
    var paths = eds.Endpoints
        .OfType<RouteEndpoint>()
        .Select(e => e.RoutePattern.RawText)
        .Where(p => !string.IsNullOrEmpty(p) && p != "/")
        .Distinct()
        .OrderBy(p => p);

    var sb = new StringBuilder();
    sb.Append("<!doctype html><meta charset=\"utf-8\"><title>C# VulnApp — endpoints</title>");
    sb.Append("<style>body{font-family:system-ui,sans-serif;max-width:64rem;margin:2rem auto;padding:0 1rem}"
        + "td{border:1px solid #ddd;padding:.35rem .6rem}table{border-collapse:collapse;width:100%}"
        + "code{background:#f4f4f4;padding:.1rem .3rem;border-radius:3px}"
        + ".warn{background:#fff3cd;border:1px solid #ffe69c;padding:.6rem 1rem;border-radius:6px}</style>");
    sb.Append("<p class=\"warn\">⚠️ Intentionally vulnerable demo app — for security education only.</p>");
    sb.Append("<h1>C# VulnApp</h1><p>Deliberately vulnerable ASP.NET Core app demonstrating OWASP "
        + "Top 10 code-level issues with multiple permutations per category.</p><table>");
    foreach (var p in paths) sb.Append($"<tr><td><code>{p}</code></td></tr>");
    sb.Append("</table>");
    return Results.Content(sb.ToString(), "text/html");
});

app.Run("http://127.0.0.1:5001");
