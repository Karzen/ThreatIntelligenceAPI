using System.Diagnostics;
using System.Runtime.InteropServices.ComTypes;
using ThreatIntelAPI.Domain.Interfaces;
using ThreatIntelAPI.Domain.Models;

namespace ThreatIntelAPI.Infrastructure.Scanners.Decorators;

public class LoggingThreatScanner : IThreatScanner
{

    private readonly IThreatScanner _inner;
    private readonly ILogger<LoggingThreatScanner> _logger;

    public string Name => $"{_inner.Name}[Logged]";
    public bool IsAvailible() => _inner.IsAvailible();


    public LoggingThreatScanner(IThreatScanner inner, ILogger<LoggingThreatScanner> logger)
    {
        _inner = inner;
        _logger = logger;
    }
    
    public async Task<ThreatEntry> ScanIpAsync(string ipAddress)
    {
        _logger.LogInformation($"[{_inner.Name}] Scanning {ipAddress}");

        var sw = Stopwatch.StartNew();

        try
        {
            var result = await _inner.ScanIpAsync(ipAddress);
            sw.Stop();

            _logger.LogInformation($"[{_inner.Name}] {ipAddress} -> {result.IsMalicious} ({sw.ElapsedMilliseconds}ms)");

            return result;
        }
        catch 
        {
            sw.Stop();
            _logger.LogError($"[{_inner}] Failed scanning {ipAddress} after {sw.ElapsedMilliseconds}");
            throw;
        }

    }
}