using System.Text.Json;
using ThreatIntelAPI.Domain.Interfaces;
using ThreatIntelAPI.Domain.Models;

namespace ThreatIntelAPI.Infrastructure.Scanners;

public class VirusTotalScanner : IThreatScanner
{
    private readonly HttpClient _httpClient;
    private readonly string? _apiKey;

    public VirusTotalScanner(HttpClient httpClient, string? apiKey)
    {
        _httpClient = httpClient;
        _apiKey = apiKey;
    }

    public string Name => "Virus Total Scanner";

    public bool IsAvailible() => !string.IsNullOrEmpty(_apiKey);

    public async Task<ThreatEntry> ScanIpAsync(string ipAddress)
    {
        _httpClient.DefaultRequestHeaders.Remove("x-apikey");
        _httpClient.DefaultRequestHeaders.Add("x-apikey", _apiKey);

        var response = await _httpClient.GetAsync($"https://www.virustotal.com/api/v3/ip_addresses/{ipAddress}");

        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"VirusTotal returned: {(int)response.StatusCode}");

        var json = await response.Content.ReadAsStringAsync();

        using var doc = JsonDocument.Parse(json);

        var stats = doc.RootElement.GetProperty("data").GetProperty("attributes").GetProperty("last_analysis_stats");

        int maliciousCount = stats.GetProperty("malicious").GetInt32();
        int suspiciousCount = stats.GetProperty("suspicious").GetInt32();

        bool isMalicious = maliciousCount > 0 || suspiciousCount > 2;

        var type = isMalicious ? ThreatType.Malware : ThreatType.Unknown;

        return new ThreatEntry(ipAddress, type, isMalicious);
    }
}