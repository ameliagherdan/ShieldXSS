namespace ShieldXSS.Models
{
    public class AttackDetectionResult
    {
        public bool IsMalicious { get; set; }
        public string? ThreatType { get; set; }
        public string? PatternFound { get; set; }
        public string? InputSample { get; set; }
    }
}