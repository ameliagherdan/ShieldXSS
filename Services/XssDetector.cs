using System.Linq;
using System.Text.RegularExpressions;
using ShieldXSS.Models;
using ShieldXSS.Services.Interfaces;

namespace ShieldXSS.Services.AttackDetection
{
    public class XssDetector : IXssDetector
    {
        private readonly ShieldXSSOptions _options;
        private readonly Regex[] _patterns;

        public XssDetector(ShieldXSSOptions options)
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
                        ThreatType = "XSS",
                        PatternFound = pattern.ToString(),
                        InputSample = SanitizeSample(input)
                    };
                }
            }
            return new AttackDetectionResult { IsMalicious = false };
        }

        private Regex[] CompilePatterns() => _options.CustomXSSPatterns
            .Concat(DefaultPatterns())
            .Select(p => new Regex(p, RegexOptions.Compiled | RegexOptions.IgnoreCase))
            .ToArray();

        private static string[] DefaultPatterns() => new[]
        {
            @"<script[^>]*>.*?</script>",
            @"javascript\s*:",
            @"on\w+\s*=",
            @"eval\s*\(",
            @"document\.(cookie|location)",
            @"<iframe[^>]*>",
            @"vbscript\s*:",
            @"<\s*img[^>]*src\s*=",
            @"<\s*link[^>]*href\s*=",
            @"expression\s*\("
        };

        private static string SanitizeSample(string input) => 
            input.Length > 50 ? input[..47] + "..." : input;
    }
}