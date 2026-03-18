using ThreatIntelAPI.Domain.Models;

namespace ThreatIntelAPI.Controllers;

public record ScanRequest(string IpAddress);

public record ErrorResponse(string Message);

public record ScanResponse(
    string IpAddress,
    string ThreatType,
    bool IsMalicious,
    int DetectionCount,
    DateTime DetectedAt,
    string Summary)
{
    public static ScanResponse From(ThreatEntry entry) => new(entry.IpAddress,
        entry.Type.ToString(),
        entry.IsMalicious,
        entry.DetectionCount,
        entry.DetectedAt,
        entry.ToString());
}