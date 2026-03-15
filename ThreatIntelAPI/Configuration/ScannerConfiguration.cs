namespace ThreatIntelAPI.Configuration;

public class ScannerConfiguration
{
    public string Type { get; set; } = "LocalBlocklist";
    public string? ApiKey { get; set; }
    public int TimeoutMs { get; set; } = 5000;
    public bool EnableFallback { get; set; } = true;
    public string[] BlockListIPs { get; set; } = Array.Empty<string>();
}