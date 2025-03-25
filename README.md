# 🛡️ ShieldXSS - ASP.NET Core Security Middleware

Security middleware for ASP.NET Core applications, providing robust protection against XSS, SQL injection, and brute-force attacks.

## Features

✅ **XSS Protection**  
✅ **SQL Injection Detection**  
✅ **Rate Limiting**  
✅ **Security Headers**  
✅ **Custom Pattern Support**  
✅ **Attack Telemetry**

## Installation

### .NET CLI
```bash
dotnet add package ShieldXSS
```

### Package Manager
```powershell
Install-Package ShieldXSS
```

## Quick Start

1. Add services in `Program.cs`:
```csharp
builder.Services.AddShieldXSS(options => {
    options.MaxAttempts = 5;
    options.BlockedResponseMessage = "Request blocked by security system";
});
```

2. Add middleware:
```csharp
app.UseShieldXSS();
```

## Configuration

```csharp
builder.Services.AddShieldXSS(options => {
    // Core Protection
    options.EnableXSSProtection = true;
    options.EnableSQLInjectionProtection = true;
    
    // Rate Limiting
    options.EnableRateLimiting = true;
    options.MaxAttempts = 5;
    options.TimeWindow = TimeSpan.FromMinutes(15);
    
    // Response Handling
    options.HoneypotUrl = "/security-alert";
    options.BlockedResponseMessage = "Request blocked";
    
    // Custom Patterns
    options.CustomXSSPatterns = new[] { @"<\s*malicious-tag" };
    options.CustomSQLPatterns = new[] { @"\bEXEC\s+SP_" };
    
    // Telemetry
    options.EnableTelemetry = true;
});
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `EnableXSSProtection` | `bool` | `true` | Enable XSS detection |
| `CustomXSSPatterns` | `string[]` | `[]` | Additional XSS regex patterns |
| `EnableRateLimiting` | `bool` | `true` | Enable IP-based rate limiting |
| `HoneypotUrl` | `string?` | `null` | Redirect attackers to this URL |

## Advanced Usage

### Custom Detection Patterns
```csharp
options.CustomXSSPatterns = new[] {
    @"<\s*custom-element",
    @"data-dangerous-attribute\s*="
};
```

### Telemetry Integration
```csharp
public class AppInsightsTelemetry : ISecurityTelemetry {
    public void TrackAttack(SecurityBlockedException ex) {
        // Implement your tracking logic
    }
}

// Registration
builder.Services.AddSingleton<ISecurityTelemetry, AppInsightsTelemetry>();
```

## Sample Attacks

Test your protection with these payloads:

```bash
# XSS
curl "https://yourapp.com/?input=<script>alert(1)</script>"

# SQL Injection
curl -X POST -d "query=SELECT * FROM Users" https://yourapp.com/submit

# Rate Limiting Test
for i in {1..6}; do
  curl "https://yourapp.com/?input=test$i"
done
```

## Performance

ShieldXSS is optimized for:
- **Low Latency**: Average 2ms overhead per request
- **Memory Efficiency**: <1MB heap allocation
- **Scalability**: Thread-safe concurrent operations

## License

MIT License - See [LICENSE](LICENSE) for details

---

**ShieldXSS** is maintained by Amelia Gherdan.  
Found a bug? [Open an issue](https://github.com/ameliagherdan/ShieldXSS/issues)