using Microsoft.Extensions.DependencyInjection;
using ShieldXSS.Services;
using ShieldXSS.Services.AttackDetection;
using ShieldXSS.Services.Interfaces;

namespace ShieldXSS.Extensions
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddShieldXSS(this IServiceCollection services)
        {
            services.AddSingleton<IRateLimitService, RateLimitService>();
            services.AddSingleton<ISqlInjectionDetector, SqlInjectionDetector>();
            services.AddSingleton<XssDetector, XssDetector>();
            return services;
        }
    }
}