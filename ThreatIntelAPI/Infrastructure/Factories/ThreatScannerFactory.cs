using Microsoft.Extensions.Caching.Memory;
using ThreatIntelAPI.Configuration;
using ThreatIntelAPI.Domain.Interfaces;
using ThreatIntelAPI.Infrastructure.Scanners;
using ThreatIntelAPI.Infrastructure.Scanners.Decorators;

namespace ThreatIntelAPI.Infrastructure.Factories;

public class ThreatScannerFactory
{
    private readonly ScannerConfiguration _config;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IMemoryCache _cache;
    private readonly ILoggerFactory _loggerFactory;

    private Dictionary<string, Func<IThreatScanner>> _builders;


    public ThreatScannerFactory(ScannerConfiguration scannerConfiguration, IHttpClientFactory httpClientFactory,
        IMemoryCache cache, ILoggerFactory loggerFactory)
    {
        _config = scannerConfiguration;
        _httpClientFactory = httpClientFactory;
        _cache = cache;
        _loggerFactory = loggerFactory;


        _builders = new Dictionary<string, Func<IThreatScanner>>
        {
            ["VirusTotal"] = CreateVirusTotal,
            ["LocalBlocklist"] = CreateLocalBlocklist,
        };
    }

    public IEnumerable<IThreatScanner> CreateAll()
    {
        var scanners = new List<IThreatScanner>();

        scanners.Add(WrapWithDecorators(CreatePrimary()));

        if (_config.EnableFallback && _config.Type != "LocalBlocklist")
            scanners.Add(CreateLocalBlocklist());

        return scanners;
    }

    private IThreatScanner CreatePrimary()
    {
        if (!_builders.TryGetValue(_config.Type, out var builder))
            throw new InvalidOperationException(
                $"Unknown scanner type: {_config.Type} | Availible scanners: {string.Join(", ", _builders.Keys)}");

        return builder();
    }

    private IThreatScanner WrapWithDecorators(IThreatScanner scanner)
    {
        IThreatScanner wrapped = new CachingThreatScanner(scanner, _cache);
        wrapped = new LoggingThreatScanner(scanner, _loggerFactory.CreateLogger<LoggingThreatScanner>());

        return wrapped;
    }

    private IThreatScanner CreateVirusTotal()
    {
        if (string.IsNullOrEmpty(_config.ApiKey))
            throw new InvalidOperationException("VirusTotal requires an API key. ");

        var client = _httpClientFactory.CreateClient("VirusTotal");
        client.Timeout = TimeSpan.FromMilliseconds(_config.TimeoutMs);

        return new VirusTotalScanner(client, _config.ApiKey);
    }

    private IThreatScanner CreateLocalBlocklist() => new LocalBlocklistScanner(_config.BlockListIPs);
}