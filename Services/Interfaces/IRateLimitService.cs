using System.Net;

namespace ShieldXSS.Services.Interfaces
{
    public interface IRateLimitService
    {
        bool IsBlocked(IPAddress ipAddress);
        void TrackRequest(IPAddress ipAddress);
    }
}