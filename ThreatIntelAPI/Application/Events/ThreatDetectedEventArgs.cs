using ThreatIntelAPI.Domain.Models;

namespace ThreatIntelAPI.Application.Events;

public class ThreatDetectedEventArgs : EventArgs
{
    public ThreatEntry Entry { get; }
    public DateTime DetectedAt { get; }
    public string DetectedBy { get; }

    public ThreatDetectedEventArgs(ThreatEntry entry, string detectedBy)
    {
        Entry = entry;
        DetectedBy = detectedBy;
        DetectedAt = DateTime.UtcNow;
    }
}