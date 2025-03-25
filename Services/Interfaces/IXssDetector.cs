using ShieldXSS.Models;

namespace ShieldXSS.Services.Interfaces
{
    public interface IXssDetector
    {
        AttackDetectionResult Analyze(string input);
    }
}