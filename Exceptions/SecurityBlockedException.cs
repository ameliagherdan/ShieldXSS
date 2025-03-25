using System;

namespace ShieldXSS.Exceptions
{
    public class SecurityBlockedException : Exception
    {
        public string ThreatType { get; }
        public string PatternFound { get; }
        public string InputSample { get; }

        public SecurityBlockedException(string threatType, string pattern, string input)
            : base($"Security violation: {threatType}")
        {
            ThreatType = threatType;
            PatternFound = pattern;
            InputSample = input;
        }
    }
}