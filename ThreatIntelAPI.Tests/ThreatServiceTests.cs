using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using ThreatIntelAPI.Application.Events;
using Xunit;
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

    private static ThreatEntry CleanEntry(string ip = "1.2.3.4") => new(ip, ThreatType.Unknown, false);


    [Fact]
    public async Task CheckIp_ScansAndSaves_WhenNotRecentlyScanned()
    {
        var (scanner, repo, service) = BuildService();

        repo.Setup(r => r.WasRecentlyScannedAsync("1.2.3.4", 6)).ReturnsAsync(false);

        scanner.Setup(s => s.ScanIpAsync("1.2.3.4")).ReturnsAsync(MaliciousEntry());

        var result = await service.CheckIpAsync("1.2.3.4");

        scanner.Verify(s => s.ScanIpAsync("1.2.3.4"), Times.Once);
        repo.Verify(r => r.SaveAsync(It.IsAny<ThreatEntry>()), Times.Once);

        result.IpAddress.Should().Be("1.2.3.4");
        result.IsMalicious.Should().BeTrue();
    }

    [Fact]
    public async Task CheckIp_ScansAndSaves_WhenRecentlyScanned()
    {
        var (scanner, repo, service) = BuildService();

        var cached = MaliciousEntry();

        repo.Setup(r => r.WasRecentlyScannedAsync("1.2.3.4", 6)).ReturnsAsync(true);

        repo.Setup(r => r.FindByIpAsync("1.2.3.4")).ReturnsAsync(cached);

        var result = await service.CheckIpAsync("1.2.3.4");

        scanner.Verify(s => s.ScanIpAsync(It.IsAny<string>()), Times.Never);
        repo.Verify(r => r.IncrementDetectionCountAsync("1.2.3.4"), Times.Once);
        result.Should().Be(cached);
    }

    [Fact]
    public async Task CheckIp_ScansAnyway_WhenRecentlyScannedButNotFound()
    {
        var (scanner, repo, service) = BuildService();

        repo.Setup(r => r.WasRecentlyScannedAsync("1.2.3.4", 6)).ReturnsAsync(true);

        repo.Setup(r => r.FindByIpAsync("1.2.3.4")).ReturnsAsync((ThreatEntry?)null);

        scanner.Setup(s => s.ScanIpAsync("1.2.3.4")).ReturnsAsync(MaliciousEntry());

        await service.CheckIpAsync("1.2.3.4");

        scanner.Verify(s => s.ScanIpAsync("1.2.3.4"), Times.Once);
    }


    [Fact]
    public async Task CheckIp_FiresThreatDetectedEvent_WhenMaliciousFound()
    {
        var (scanner, repo, service) = BuildService();

        repo.Setup(r => r.WasRecentlyScannedAsync(It.IsAny<string>(), It.IsAny<int>())).ReturnsAsync(false);

        scanner.Setup(s => s.ScanIpAsync("1.2.3.4")).ReturnsAsync(MaliciousEntry());

        ThreatDetectedEventArgs? captured = null;

        service.ThreatDetected += (_, args) => captured = args;

        await service.CheckIpAsync("1.2.3.4");

        captured.Should().NotBeNull();
        captured!.Entry.IpAddress.Should().Be("1.2.3.4");
        captured!.Entry.IsMalicious.Should().BeTrue();
        captured!.DetectedBy.Should().Be("MockScanner");
    }

    [Fact]
    public async Task CheckIP_DoesNotFireEvent_WhenEntryIsClean()
    {
        var (scanner, repo, service) = BuildService();

        repo.Setup(r => r.WasRecentlyScannedAsync(It.IsAny<string>(), It.IsAny<int>())).ReturnsAsync(false);

        scanner.Setup(s => s.ScanIpAsync("1.2.3.4")).ReturnsAsync(CleanEntry());

        bool fired = false;

        service.ThreatDetected += (_, _) => fired = true;

        await service.CheckIpAsync("1.2.3.4");

        fired.Should().BeFalse();
    }

    [Fact]
    public async Task CheckIp_ThrowsInvalidOperation_WhenNoScannersAvailable()
    {
        var (scanner, repo, service) = BuildService(false);

        repo.Setup(r => r.WasRecentlyScannedAsync(It.IsAny<string>(), It.IsAny<int>()))
            .ReturnsAsync(false);

        var act = async () => await service.CheckIpAsync("1.2.3.4");

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("All scanners failed in checking this ip address");
    }

    [Fact]
    public async Task CheckIp_UsesFallback_WhenPrimaryScannerUnavailable()
    {
        // More scanners here so we build the scanner manually
        var primary = new Mock<IThreatScanner>();
        var fallback = new Mock<IThreatScanner>();
        var repo = new Mock<IThreatRepository>();
        var logger = new Mock<ILogger<ThreatService>>();

        primary.Setup(s => s.IsAvailible()).Returns(false);
        primary.Setup(s => s.Name).Returns("Primary");

        fallback.Setup(s => s.IsAvailible()).Returns(true);
        fallback.Setup(s => s.Name).Returns("Fallback");
        fallback.Setup(s => s.ScanIpAsync("1.2.3.4")).ReturnsAsync(MaliciousEntry());

        repo.Setup(r => r.WasRecentlyScannedAsync(It.IsAny<string>(), It.IsAny<int>())).ReturnsAsync(false);

        var service = new ThreatService(new[] { primary.Object, fallback.Object }, repo.Object, logger.Object);

        await service.CheckIpAsync("1.2.3.4");

        primary.Verify(s => s.ScanIpAsync(It.IsAny<string>()), Times.Never);
        fallback.Verify(s => s.ScanIpAsync("1.2.3.4"), Times.Once);
    }


    [Fact]
    public async Task GetStats_ReturnsCorrectCounts()
    {
        var (scanner, repo, service) = BuildService();

        repo.Setup(r => r.GetAllAsync()).ReturnsAsync(new List<ThreatEntry>
        {
            new("1.1.1.1", ThreatType.Malware, true),
            new("2.2.2.2", ThreatType.Ransomware, true),
            new("3.3.3.3", ThreatType.Unknown, false),
            new("4.4.4.4", ThreatType.Phishing, true),
        });

        var stats = await service.GetStatsAsync();

        stats.TotalScans.Should().Be(4);
        stats.TotalMalicious.Should().Be(3);
        stats.ByType.Should().ContainKey("Malware");
        stats.ByType.Should().ContainKey("Ransomware");
        stats.ByType.Should().ContainKey("Phishing");
        stats.ByType.Should().ContainKey("Unknown");
    }

    [Fact]
    public async Task GetStats_ReturnsZeroes_WhenNoScans()
    {
        var (scanner, repo, service) = BuildService();

        repo.Setup(r => r.GetAllAsync())
            .ReturnsAsync(new List<ThreatEntry>());

        var stats = await service.GetStatsAsync();

        stats.TotalScans.Should().Be(0);
        stats.TotalMalicious.Should().Be(0);
        stats.TopThreats.Should().BeEmpty();
    }
}