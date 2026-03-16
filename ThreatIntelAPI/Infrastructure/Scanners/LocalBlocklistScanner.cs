using ThreatIntelAPI.Domain.Interfaces;
using ThreatIntelAPI.Domain.Models;

namespace ThreatIntelAPI.Infrastructure.Scanners;

public class LocalBlocklistScanner : IThreatScanner
{

    private readonly HashSet<string> _blocklist;

    public string Name => "LocalBlocklist";
    
    public bool IsAvailible() => true;

    public LocalBlocklistScanner(IEnumerable<string> blocklist)
    {
        _blocklist = new HashSet<string>(blocklist);
    }

    public async Task<ThreatEntry> ScanIpAsync(string ipAddress)
    {
        await Task.CompletedTask;

        bool hit = _blocklist.Contains(ipAddress);

        var type = hit ? ThreatType.Blocklisted : ThreatType.Unknown;

        return new ThreatEntry(ipAddress, type, hit);

    }
}