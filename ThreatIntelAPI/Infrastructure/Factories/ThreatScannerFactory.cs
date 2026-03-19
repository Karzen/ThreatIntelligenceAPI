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

    private Dictionary<string, Func<IThreatScanner?>> _builders;


    public ThreatScannerFactory(ScannerConfiguration scannerConfiguration, IHttpClientFactory httpClientFactory,
        IMemoryCache cache, ILoggerFactory loggerFactory)
    {
        _config = scannerConfiguration;
        _httpClientFactory = httpClientFactory;
        _cache = cache;
        _loggerFactory = loggerFactory;


        _builders = new Dictionary<string, Func<IThreatScanner?>>
        {
            ["VirusTotal"] = CreateVirusTotal,
            ["LocalBlocklist"] = CreateLocalBlocklist,
        };
    }

    public IEnumerable<IThreatScanner> CreateAll()
    {
        var scanners = new List<IThreatScanner>();

        if (_config.EnableFallback) // If fallback is enabled we want to add all scanners 
        {
            foreach (var (_, func) in _builders)
            {
                var scanner = func();
                if (scanner is not null)
                    scanners.Add(WrapWithDecorators(scanner));
            }
        }
        else
        {
            var scanner = CreatePrimary();
            if (scanner is null)
                throw new InvalidOperationException($"{_config.Type} scanner not availible");
            scanners.Add(scanner);
        }

        return scanners;
    }

    private IThreatScanner? CreatePrimary()
    {
        if (!_builders.TryGetValue(_config.Type, out var builder))
            throw new InvalidOperationException(
                $"Unknown scanner type: {_config.Type} | Availible scanners: {string.Join(", ", _builders.Keys)}");

        return builder();
    }

    private IThreatScanner WrapWithDecorators(IThreatScanner scanner)
    {
        IThreatScanner wrapped = new CachingThreatScanner(scanner, _cache);
        wrapped = new LoggingThreatScanner(wrapped, _loggerFactory.CreateLogger<LoggingThreatScanner>());

        return wrapped;
    }

    private IThreatScanner? CreateVirusTotal()
    {
        var client = _httpClientFactory.CreateClient("VirusTotal");
        client.Timeout = TimeSpan.FromMilliseconds(_config.TimeoutMs);

        var scanner = new VirusTotalScanner(client, _config.ApiKey);

        return scanner.IsAvailible() ? scanner : null;
    }

    private IThreatScanner CreateLocalBlocklist() => new LocalBlocklistScanner(_config.BlockListIPs);
}