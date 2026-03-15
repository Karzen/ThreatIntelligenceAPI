using ThreatIntelAPI.Domain.Models;

namespace ThreatIntelAPI.Domain.Interfaces;

public interface IThreatScanner
{
    string Name { get;  }
    bool IsAvailible();
    Task<ThreatEntry> ScanIpAsync(string ipAddress);
}