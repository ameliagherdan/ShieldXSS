using ShieldXSS.Models;

namespace ShieldXSS.Services.Interfaces
{
    public interface ISqlInjectionDetector : IAttackDetector
    {
        AttackDetectionResult Analyze(string input);
    }
}