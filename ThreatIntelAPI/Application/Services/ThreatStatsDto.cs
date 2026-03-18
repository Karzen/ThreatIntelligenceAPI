namespace ThreatIntelAPI.Application.Services;

public class ThreatStatsDto
{
    public int TotalScans { get; set; }
    public int TotalMalicious { get; set; }
    public Dictionary<string, int> ByType { get; set; } = new();
    public List<string> TopThreats { get; set; } = new();
}