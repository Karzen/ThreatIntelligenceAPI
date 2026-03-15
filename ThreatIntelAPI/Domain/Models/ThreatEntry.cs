namespace ThreatIntelAPI.Domain.Models;

public class ThreatEntry
{
    public string IpAddress
    {
        get => field;
        init
        {
            // Clean and check if the ip is valid
            string cleaned = value?.Trim() ?? "";

            if (string.IsNullOrWhiteSpace(cleaned))
                throw new ArgumentException("IP address cannot be empty");
            if (!IsValidIp(cleaned))
                throw new ArgumentException("IP address is not a valid IP");
            field = cleaned;
        }
    }

    public ThreatType Type { get; private set; }
    public bool IsMalicious { get; private set; }
    public DateTime DetectedAt { get; private set; }
    public int DetectionCount { get; private set; }

    public ThreatEntry(string ipAddress, ThreatType type, bool isMalicious)
    {
        IpAddress = ipAddress;
        Type = type;
        IsMalicious = isMalicious;
        DetectedAt = DateTime.UtcNow;
        DetectionCount = 1;
    }

    public ThreatEntry(string ipAddress, ThreatType type, bool isMalicious, DateTime detectedAt, int detectionCount) :
        this(ipAddress, type,
            isMalicious)
    {
        DetectedAt = detectedAt;
        DetectionCount = detectionCount;
    }

    public void IncrementDetection() => DetectionCount++;

    public bool IsRecent(int withingHours = 24)
    {
        return (DateTime.UtcNow - DetectedAt).Hours <= withingHours;
    }

    public override string ToString()
    {
        string isMalicious = IsMalicious ? "Malicious" : "Clean";
        return
            $"[{isMalicious}] {IpAddress} | Type: {Type} | TotalDetections: {DetectionCount} | DetectedAt: {DetectedAt}";
    }

    public static bool IsValidIp(string ip) => System.Net.IPAddress.TryParse(ip, out _);
}