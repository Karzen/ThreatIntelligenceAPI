using ThreatIntelAPI.Domain.Models;

namespace ThreatIntelAPI.Domain.Interfaces;

public interface IThreatRepository
{
    Task SaveAsync(ThreatEntry entry);
    Task<ThreatEntry?> FindByIpAsync(string ipAddress);
    Task<List<ThreatEntry>> GetAllAsync();
    Task<List<ThreatEntry>> GetRecentAsync(int hours = 24);
    Task<List<ThreatEntry>> GetMaliciousAsync();
    Task<bool> WasRecentlyScannedAsync(string ipAddress, int withinHours = 6);
    Task<int> GetTotalScanCountAsync();
    Task IncrementDetectionCountAsync(string ipAddress);
    Task DeleteOlderThanAsync(int days);
}