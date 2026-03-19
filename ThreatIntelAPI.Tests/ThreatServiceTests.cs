using Microsoft.Extensions.Logging;
using Moq;
using ThreatIntelAPI.Application.Services;
using ThreatIntelAPI.Domain.Interfaces;
using ThreatIntelAPI.Domain.Models;

namespace ThreatIntelAPI.Tests;

public class ThreatServiceTests
{
    private static (Mock<IThreatScanner> scanner, Mock<IThreatRepository> repo, ThreatService service)
        BuildService(bool scannerAvailible = true)
    {

        var scanner = new Mock<IThreatScanner>();
        scanner.Setup(s => s.IsAvailible()).Returns(scannerAvailible);
        scanner.Setup(s => s.Name).Returns("MockScanner");

        var repo = new Mock<IThreatRepository>();
        var logger = new Mock<ILogger<ThreatService>>();

        var service = new ThreatService(new[] { scanner.Object }, repo.Object, logger.Object);

        return (scanner, repo, service);
    }

    private static ThreatEntry MaliciousEntry(string ip = "1.2.3.4") => new(ip, ThreatType.Malware, true);

    private static ThreatEntry CleanEntry(string ip) => new(ip, ThreatType.Unknown, false);
    
    

}