using System;

namespace ShieldXSS.Models
{
    public class ShieldXSSOptions
    {
        public bool EnableXSSProtection { get; set; } = true;
        public bool EnableSQLInjectionProtection { get; set; } = true;
        public bool EnableRateLimiting { get; set; } = true;
        public int MaxAttempts { get; set; } = 5;
        public TimeSpan TimeWindow { get; set; } = TimeSpan.FromMinutes(15);
        public string BlockedResponseMessage { get; set; } = "Request blocked for security reasons";
        public string? HoneypotUrl { get; set; }
        public bool EnableTelemetry { get; set; }
        public string[] CustomSQLPatterns { get; set; } = Array.Empty<string>();
        public string[] CustomXSSPatterns { get; set; } = Array.Empty<string>();
    }
}