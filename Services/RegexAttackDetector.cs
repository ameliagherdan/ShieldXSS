using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using ShieldXSS.Models;
using ShieldXSS.Services.Interfaces;

namespace ShieldXSS.Services;

public class RegexAttackDetector : IAttackDetector
    {
        private readonly ShieldXSSOptions _options;
        private readonly Regex[] _sqlPatterns;
        private readonly Regex[] _xssPatterns;

        public RegexAttackDetector(ShieldXSSOptions options)
        {
            _options = options;
            _sqlPatterns = CompilePatterns(GetSQLPatterns());
            _xssPatterns = CompilePatterns(GetXSSPatterns());
        }

        public AttackDetectionResult Analyze(string input)
        {
            if (_options.EnableSQLInjectionProtection)
            {
                var sqlResult = CheckPatterns(input, _sqlPatterns);
                if (sqlResult.IsMalicious)
                {
                    sqlResult.ThreatType = "SQL Injection";
                    return sqlResult;
                }
            }

            if (_options.EnableXSSProtection)
            {
                var xssResult = CheckPatterns(input, _xssPatterns);
                if (xssResult.IsMalicious)
                {
                    xssResult.ThreatType = "XSS";
                    return xssResult;
                }
            }

            return new AttackDetectionResult { IsMalicious = false };
        }

        private AttackDetectionResult CheckPatterns(string input, Regex[] patterns)
        {
            foreach (var regex in patterns)
            {
                var match = regex.Match(input);
                if (match.Success)
                {
                    return new AttackDetectionResult
                    {
                        IsMalicious = true,
                        PatternFound = regex.ToString(),
                        InputSample = input[..Math.Min(50, input.Length)]
                    };
                }
            }
            return new AttackDetectionResult { IsMalicious = false };
        }

        private Regex[] CompilePatterns(IEnumerable<string> patterns) => 
            patterns.Select(p => new Regex(p, RegexOptions.Compiled | RegexOptions.IgnoreCase)).ToArray();

        private string[] GetSQLPatterns() => _options.CustomSQLPatterns
            .Concat(DefaultSQLPatterns())
            .ToArray();

        private string[] GetXSSPatterns() => _options.CustomXSSPatterns
            .Concat(DefaultXSSPatterns())
            .ToArray();

        private static string[] DefaultSQLPatterns() => new[]
        {
            @"(\b(SELECT|INSERT|UPDATE|DELETE|UNION|EXEC|ALTER|DROP|TRUNCATE|LOAD_FILE)\b)",
            @"(\b(OR|AND)\s+[\d\w]+\s*=\s*[\d\w]+)",
            @"(--|;|\/\*|\*\/|@@\w+|CHAR\(\d+\))"
        };

        private static string[] DefaultXSSPatterns() => new[]
        {
            @"<script[^>]*>.*?</script>",
            @"javascript\s*:",
            @"on\w+\s*=",
            @"eval\s*\(",
            @"document\.(cookie|location)",
            @"<iframe[^>]*>",
            @"vbscript\s*:"
        };
    }