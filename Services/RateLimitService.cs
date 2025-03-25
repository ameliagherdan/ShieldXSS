using System;
using System.Net;
using System.Collections.Concurrent;
using System.Linq;
using ShieldXSS.Models;
using ShieldXSS.Services.Interfaces;

namespace ShieldXSS.Services
{
    public class RateLimitService : IRateLimitService
    {
        private readonly ConcurrentDictionary<IPAddress, RateLimitRecord> _ipTracker = new();
        private readonly ShieldXSSOptions _options;

        public RateLimitService(ShieldXSSOptions options)
        {
            _options = options;
        }

        public bool IsBlocked(IPAddress ipAddress)
        {
            CleanupExpiredRecords();
            return _ipTracker.TryGetValue(ipAddress, out var record) && 
                   record.Count >= _options.MaxAttempts &&
                   DateTime.UtcNow - record.FirstAttempt < _options.TimeWindow;
        }

        public void TrackRequest(IPAddress ipAddress)
        {
            _ipTracker.AddOrUpdate(ipAddress,
                _ => new RateLimitRecord(),
                (_, existing) => existing.Increment());
        }

        private void CleanupExpiredRecords()
        {
            var cutoff = DateTime.UtcNow - _options.TimeWindow;
            foreach (var entry in _ipTracker.Where(kvp => kvp.Value.FirstAttempt < cutoff).ToList())
            {
                _ipTracker.TryRemove(entry.Key, out _);
            }
        }

        private class RateLimitRecord
        {
            public int Count { get; private set; } = 1;
            public DateTime FirstAttempt { get; } = DateTime.UtcNow;

            public RateLimitRecord Increment()
            {
                Count++;
                return this;
            }
        }
    }
}