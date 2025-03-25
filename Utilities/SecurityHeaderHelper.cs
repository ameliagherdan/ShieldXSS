using Microsoft.AspNetCore.Http;

namespace ShieldXSS.Utilities
{
    public static class SecurityHeaderHelper
    {
        public static void ApplySecurityHeaders(HttpContext context)
        {
            var headers = context.Response.Headers;
            headers["X-Content-Type-Options"] = "nosniff";
            headers["X-Frame-Options"] = "DENY";
            headers["X-XSS-Protection"] = "1; mode=block";
            headers["Content-Security-Policy"] = "default-src 'self'";
            headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
        }
    }
}