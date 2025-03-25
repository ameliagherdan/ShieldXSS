using System.Linq;
using System.Text.RegularExpressions;
using ShieldXSS.Models;
using ShieldXSS.Services.Interfaces;

namespace ShieldXSS.Services.AttackDetection
{
    public class SqlInjectionDetector : ISqlInjectionDetector
    {
        private readonly ShieldXSSOptions _options;
        private readonly Regex[] _patterns;

        public SqlInjectionDetector(ShieldXSSOptions options)
        {
            _options = options;
            _patterns = CompilePatterns();
        }

        public AttackDetectionResult Analyze(string input)
        {
            foreach (var pattern in _patterns)
            {
                var match = pattern.Match(input);
                if (match.Success)
                {
                    return new AttackDetectionResult
                    {
                        IsMalicious = true,
                        ThreatType = "SQL_INJECTION",
                        PatternFound = pattern.ToString(),
                        InputSample = SanitizeSample(input)
                    };
                }
            }
            return new AttackDetectionResult { IsMalicious = false };
        }

        private Regex[] CompilePatterns() => _options.CustomSQLPatterns
            .Concat(DefaultPatterns())
            .Select(p => new Regex(p, RegexOptions.Compiled | RegexOptions.IgnoreCase))
            .ToArray();

        private static string[] DefaultPatterns() => new[]
        {
            @"(\b(SELECT|INSERT|UPDATE|DELETE|UNION|EXEC|ALTER|DROP|TRUNCATE|LOAD_FILE)\b)",
            @"(\b(OR|AND)\s+[\d\w]+\s*=\s*[\d\w]+)",
            @"(--|;|\/\*|\*\/|@@\w+|CHAR\(\d+\))"
        };

        private static string SanitizeSample(string input) => 
            input.Length > 50 ? input[..47] + "..." : input;
    }
}