using ThreatIntelAPI.Application.Events;
using ThreatIntelAPI.Domain.Interfaces;
using ThreatIntelAPI.Domain.Models;

namespace ThreatIntelAPI.Application.Services;

public class ThreatService
{
    private readonly IEnumerable<IThreatScanner> _scanners;
    private readonly IThreatRepository _repository;
    private readonly ILogger<ThreatService> _logger;



    public event EventHandler<ThreatDetectedEventArgs>? ThreatDetected;


    public ThreatService(IEnumerable<IThreatScanner> scanners, IThreatRepository repository, ILogger<ThreatService> logger)
    {
        _scanners = scanners;
        _repository = repository;
        _logger = logger;
    }

    public async Task<ThreatEntry> CheckIpAsync(string ipAddress)
    {
        if (await _repository.WasRecentlyScannedAsync(ipAddress))
        {
            var existing = await _repository.FindByIpAsync(ipAddress);
            if (existing is not null)
            {
                _logger.LogInformation($"Found ip: [{ipAddress}]");
                await _repository.IncrementDetectionCountAsync(ipAddress);
                return existing;
            }
        }

        var scanner = GetActiveScanner();
        var entry = await scanner.ScanIpAsync(ipAddress);
        await _repository.SaveAsync(entry);

        if (entry.IsMalicious)
            OnThreatDetected(entry, scanner.Name);

        return entry;
    }

    public async Task<List<ThreatEntry>> GetHistoryAsync(int hours = 24) => await _repository.GetRecentAsync(hours);
    
    public async Task<List<ThreatEntry>> GetMaliciousAsync() =>
        await _repository.GetMaliciousAsync();
    
    public async Task<ThreatStatsDto> GetStatsAsync()
    {
        var all = await _repository.GetAllAsync();

        return new ThreatStatsDto
        {
            TotalScans    = all.Count,
            TotalMalicious = all.Count(e => e.IsMalicious),
            ByType        = all
                .Where(e => e.IsMalicious)
                .GroupBy(e => e.Type.ToString())
                .ToDictionary(g => g.Key, g => g.Count()),
            TopThreats    = all
                .Where(e => e.IsMalicious)
                .OrderByDescending(e => e.DetectionCount)
                .Take(5)
                .Select(e => e.IpAddress)
                .ToList()
        };
    }
    
    public async Task CleanupAsync(int olderThanDays = 30) =>
        await _repository.DeleteOlderThanAsync(olderThanDays);
    
    private IThreatScanner GetActiveScanner()
    {
        var scanner = _scanners.FirstOrDefault(s => s.IsAvailible());
        if (scanner is null)
            throw new InvalidOperationException("No threat scanners are currently availible");
        
        _logger.LogInformation($"Active scanner: {scanner.Name}");
        return scanner;
    }


    protected virtual void OnThreatDetected(ThreatEntry entry, string scannerName)
    {
        var args = new ThreatDetectedEventArgs(entry, scannerName);
        ThreatDetected?.Invoke(this, args);
    }
    
}