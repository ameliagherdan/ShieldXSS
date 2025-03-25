using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using ShieldXSS.Exceptions;
using ShieldXSS.Models;
using ShieldXSS.Services.Interfaces;
using ShieldXSS.Utilities;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;

namespace ShieldXSS.Middleware
{
    public class ShieldXSSMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ShieldXSSMiddleware> _logger;
        private readonly ShieldXSSOptions _options;
        private readonly IRateLimitService _rateLimitService;
        private readonly ISqlInjectionDetector _sqlDetector;
        private readonly IXssDetector _xssDetector;

        public ShieldXSSMiddleware(
            RequestDelegate next,
            ILogger<ShieldXSSMiddleware> logger,
            IOptions<ShieldXSSOptions> options,
            IRateLimitService rateLimitService,
            ISqlInjectionDetector sqlDetector,
            IXssDetector xssDetector)
        {
            _next = next;
            _logger = logger;
            _options = options.Value;
            _rateLimitService = rateLimitService;
            _sqlDetector = sqlDetector;
            _xssDetector = xssDetector;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            SecurityHeaderHelper.ApplySecurityHeaders(context);
            var ipAddress = context.Connection.RemoteIpAddress;

            try
            {
                if (ipAddress != null && _options.EnableRateLimiting)
                {
                    CheckRateLimit(ipAddress);
                }

                if (ShouldInspectRequest())
                {
                    await InspectRequestContent(context);
                }

                await _next(context);
            }
            catch (SecurityBlockedException ex)
            {
                await HandleBlockedRequest(context, ex);
            }
        }

        private bool ShouldInspectRequest()
        {
            return _options.EnableSQLInjectionProtection || _options.EnableXSSProtection;
        }

        private async Task InspectRequestContent(HttpContext context)
        {
            var sources = new List<IEnumerable<KeyValuePair<string, StringValues>>>
            {
                context.Request.Query,
                context.Request.HasFormContentType ? context.Request.Form : new FormCollection(null),
                context.Request.Headers
            };

            // Convert cookies to compatible format
            var cookies = context.Request.Cookies
                .Select(c => new KeyValuePair<string, StringValues>(c.Key, c.Value))
                .ToList();
            sources.Add(cookies);

            foreach (var source in sources)
            {
                foreach (var entry in source)
                {
                    foreach (var value in entry.Value)
                    {
                        var result = InspectInput(value);
                        if (result.IsMalicious)
                        {
                            _rateLimitService.TrackRequest(context.Connection.RemoteIpAddress!);
                            LogSecurityEvent(context, result);
                            throw CreateSecurityException(result);
                        }
                    }
                }
            }
        }

        private AttackDetectionResult InspectInput(string input)
        {
            if (_options.EnableSQLInjectionProtection)
            {
                var sqlResult = _sqlDetector.Analyze(input);
                if (sqlResult.IsMalicious) return sqlResult;
            }

            if (_options.EnableXSSProtection)
            {
                return _xssDetector.Analyze(input);
            }

            return new AttackDetectionResult { IsMalicious = false };
        }

        private void CheckRateLimit(IPAddress ipAddress)
        {
            if (_rateLimitService.IsBlocked(ipAddress))
            {
                _logger.LogCritical("IP {IP} blocked due to rate limit violations", ipAddress);
                throw new SecurityBlockedException(
                    "RATE_LIMIT",
                    $"Exceeded {_options.MaxAttempts} attempts",
                    ipAddress.ToString());
            }
        }

        private void LogSecurityEvent(HttpContext context, AttackDetectionResult result)
        {
            var logLevel = result.ThreatType switch
            {
                "SQL_INJECTION" => LogLevel.Critical,
                "XSS" => LogLevel.Warning,
                _ => LogLevel.Information
            };

            _logger.Log(logLevel,
                "[ShieldXSS] {ThreatType} detected from {IP} | Path: {Path} | Pattern: {Pattern} | Sample: {Sample}",
                result.ThreatType,
                context.Connection.RemoteIpAddress,
                context.Request.Path,
                result.PatternFound,
                result.InputSample);
        }

        private SecurityBlockedException CreateSecurityException(AttackDetectionResult result)
        {
            return new SecurityBlockedException(
                result.ThreatType!,
                result.PatternFound!,
                result.InputSample!);
        }

        private async Task HandleBlockedRequest(HttpContext context, SecurityBlockedException ex)
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.ContentType = "text/plain";

            if (!string.IsNullOrEmpty(_options.HoneypotUrl))
            {
                context.Response.Redirect(_options.HoneypotUrl);
            }
            else
            {
                await context.Response.WriteAsync(_options.BlockedResponseMessage);
            }

            if (_options.EnableTelemetry)
            {
                var telemetry = context.RequestServices.GetService<ISecurityTelemetry>();
                telemetry?.TrackAttack(ex);
            }
        }
    }
}