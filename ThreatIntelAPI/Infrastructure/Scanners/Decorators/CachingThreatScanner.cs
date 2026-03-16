using Microsoft.Extensions.Caching.Memory;
using ThreatIntelAPI.Domain.Interfaces;
using ThreatIntelAPI.Domain.Models;

namespace ThreatIntelAPI.Infrastructure.Scanners.Decorators;

public class CachingThreatScanner : IThreatScanner
{
    private readonly IThreatScanner _inner;
    private readonly IMemoryCache _cache;
    private readonly TimeSpan _cleanDuration;
    private readonly TimeSpan _maliciousDuration;

    public CachingThreatScanner(IThreatScanner inner, IMemoryCache cache, TimeSpan? cleanDuration = null,
        TimeSpan? maliciousDuration = null)
    {
        _inner = inner;
        _cache = cache;
        _cleanDuration = cleanDuration ?? TimeSpan.FromMinutes(30);
        _maliciousDuration = maliciousDuration ?? TimeSpan.FromMinutes(60);
    }
    
    
    public string Name => $"{_inner.Name}[Cached]";
    public bool IsAvailible() => _inner.IsAvailible();

    public async Task<ThreatEntry> ScanIpAsync(string ipAddress)
    {
        var key = $"scan:{ipAddress}";

        if (_cache.TryGetValue(key, out ThreatEntry? cached))
            return cached!;

        var entry = await _inner.ScanIpAsync(ipAddress);

        var duration = entry.IsMalicious ? _maliciousDuration : _cleanDuration;
        _cache.Set(key, entry, duration);

        return entry;

    }
    
}