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


    public ThreatService(IEnumerable<IThreatScanner> scanners, IThreatRepository repository,
        ILogger<ThreatService> logger)
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

        var (entry, scannerName) = await ScanIpAsync(ipAddress);

        if (entry is null)
            throw new InvalidOperationException("All scanners failed in checking this ip address");
        
        await _repository.SaveAsync(entry);

        if (entry.IsMalicious)
            OnThreatDetected(entry, scannerName!);

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
            TotalScans = all.Count,
            TotalMalicious = all.Count(e => e.IsMalicious),
            ByType = all
                .Where(e => e.IsMalicious)
                .GroupBy(e => e.Type.ToString())
                .ToDictionary(g => g.Key, g => g.Count()),
            TopThreats = all
                .Where(e => e.IsMalicious)
                .OrderByDescending(e => e.DetectionCount)
                .Take(5)
                .Select(e => e.IpAddress)
                .ToList()
        };
    }

    public async Task CleanupAsync(int olderThanDays = 30) =>
        await _repository.DeleteOlderThanAsync(olderThanDays);


    private async Task<(ThreatEntry? ScannedEntry, string? ScannerName)> ScanIpAsync(string ipAddress)
    {
        var scanners = GetActiveScanners();
        // Try all scanners
        foreach (var scanner in scanners)
        {
            try
            {
                _logger.LogInformation($"Trying to scan {ipAddress} with {scanner.Name} scanner");
                var entry = await scanner.ScanIpAsync(ipAddress);
                return (entry, scanner.Name);
            }
            catch (Exception e)
            {
                // If a scanner fails log the error, and move on
                _logger.LogError($"Failed to scan {ipAddress} with {scanner.Name} scanner exception: {e.Message}");
            }
        }

        // If all scanners failed return null
        return (null, null);
    }

    private IEnumerable<IThreatScanner> GetActiveScanners()
    {
        var scanners = _scanners.Where(s => s.IsAvailible());
        return scanners;
    }


    protected virtual void OnThreatDetected(ThreatEntry entry, string scannerName)
    {
        var args = new ThreatDetectedEventArgs(entry, scannerName);
        ThreatDetected?.Invoke(this, args);
    }
}