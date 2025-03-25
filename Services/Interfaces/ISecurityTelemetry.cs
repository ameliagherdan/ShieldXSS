using ShieldXSS.Exceptions;

namespace ShieldXSS.Services.Interfaces
{
    public interface ISecurityTelemetry
    {
        void TrackAttack(SecurityBlockedException exception);
    }
}