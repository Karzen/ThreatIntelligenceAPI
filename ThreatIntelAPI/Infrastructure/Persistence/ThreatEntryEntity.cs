namespace ThreatIntelAPI.Infrastructure.Persistence;

public class ThreatEntryEntity
{
    public int Id { get; set; }
    public string IpAddress { get; set; } = string.Empty;
    public string ThreatType { get; set; } = string.Empty;
    public bool IsMalicious { get; set; }
    public DateTime DetectedAt { get; set; }
    public int DetectionCount { get; set; }
}