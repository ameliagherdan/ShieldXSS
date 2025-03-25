using ShieldXSS.Models;

namespace ShieldXSS.Services.Interfaces
{
    public interface IAttackDetector
    {
        AttackDetectionResult Analyze(string input);
    }
}