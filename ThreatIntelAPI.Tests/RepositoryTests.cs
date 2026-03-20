using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using ThreatIntelAPI.Domain.Models;
using ThreatIntelAPI.Infrastructure.Persistence;
using ThreatIntelAPI.Infrastructure.Repositories;
using Xunit;

namespace ThreatIntelAPI.Tests;

public class RepositoryTests
{
    private readonly AppDbContext _context;
    private readonly PostgresThreatRepository _repo;


    public RepositoryTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        _context = new AppDbContext(options);
        _repo = new PostgresThreatRepository(_context);
    }

    [Fact]
    public async Task Save_PersistsEntry_ToDatabase()
    {
        var entry = new ThreatEntry("1.2.3.4", ThreatType.Malware, true);

        await _repo.SaveAsync(entry);

        var saved = await _context.Threats.FirstOrDefaultAsync();

        saved.Should().NotBeNull();
        saved!.IpAddress.Should().Be("1.2.3.4");
        saved.IsMalicious.Should().BeTrue();
    }

    [Fact]
    public async Task FindByIp_ReturnsEntry_WhenExists()
    {
        await _repo.SaveAsync(new ThreatEntry("1.2.3.4", ThreatType.Malware, true));

        var result = await _repo.FindByIpAsync("1.2.3.4");

        result.Should().NotBeNull();
        result!.IpAddress.Should().Be("1.2.3.4");
    }

    [Fact]
    public async Task FindByIp_ReturnsNull_WhenNotFound()
    {
        var result = await _repo.FindByIpAsync("9.9.9.9");

        result.Should().BeNull();
    }

    [Fact]
    public async Task FindByIp_ReturnsMostRecent_WhenMultipleExist()
    {
        var old = new ThreatEntry("1.2.3.4", ThreatType.Unknown, false, DateTime.UtcNow.AddHours(-10), 1);

        var recent = new ThreatEntry("1.2.3.4", ThreatType.Malware, true, DateTime.UtcNow.AddHours(-1), 1);

        await _repo.SaveAsync(old);
        await _repo.SaveAsync(recent);

        var result = await _repo.FindByIpAsync("1.2.3.4");

        result!.IsMalicious.Should().BeTrue();
    }


    [Fact]
    public async Task GetRecent_ReturnsOnlyEntriesWithinTimeWindow()
    {
        await _repo.SaveAsync(new ThreatEntry(
            "1.1.1.1", ThreatType.Malware, true,
            DateTime.UtcNow.AddHours(-2), 1));

        await _repo.SaveAsync(new ThreatEntry(
            "2.2.2.2", ThreatType.Unknown, false,
            DateTime.UtcNow.AddHours(-48), 1));

        var results = await _repo.GetRecentAsync(hours: 24);

        results.Should().HaveCount(1);
        results[0].IpAddress.Should().Be("1.1.1.1");
    }

    [Fact]
    public async Task GetMalicious_ReturnsOnlyMaliciousEntries()
    {
        await _repo.SaveAsync(new ThreatEntry("1.1.1.1", ThreatType.Malware, true));
        await _repo.SaveAsync(new ThreatEntry("2.2.2.2", ThreatType.Unknown, false));
        await _repo.SaveAsync(new ThreatEntry("3.3.3.3", ThreatType.Phishing, true));

        var results = await _repo.GetMaliciousAsync();

        results.Should().HaveCount(2);
        results.Should().OnlyContain(e => e.IsMalicious);
    }

    [Fact]
    public async Task WasRecentlyScanned_ReturnsTrue_WhenScannedWithinWindow()
    {
        await _repo.SaveAsync(new ThreatEntry(
            "1.2.3.4", ThreatType.Malware, true,
            DateTime.UtcNow.AddHours(-2), 1));

        var result = await _repo.WasRecentlyScannedAsync("1.2.3.4", withinHours: 6);

        result.Should().BeTrue();
    }

    [Fact]
    public async Task WasRecentlyScanned_ReturnsFalse_WhenScannedOutsideWindow()
    {
        await _repo.SaveAsync(new ThreatEntry(
            "1.2.3.4", ThreatType.Malware, true,
            DateTime.UtcNow.AddHours(-10), 1));

        var result = await _repo.WasRecentlyScannedAsync("1.2.3.4", withinHours: 6);

        result.Should().BeFalse();
    }

    [Fact]
    public async Task IncrementDetection_IncreasesCount_ByOne()
    {
        await _repo.SaveAsync(new ThreatEntry("1.2.3.4", ThreatType.Malware, true));

        await _repo.IncrementDetectionCountAsync("1.2.3.4");

        var updated = await _repo.FindByIpAsync("1.2.3.4");
        updated!.DetectionCount.Should().Be(2);
    }


    [Fact]
    public async Task DeleteOlderThan_RemovesOldEntries_LeavesRecentOnes()
    {
        await _repo.SaveAsync(new ThreatEntry(
            "1.1.1.1", ThreatType.Malware, true,
            DateTime.UtcNow.AddDays(-40), 1)); // older than 30 days

        await _repo.SaveAsync(new ThreatEntry(
            "2.2.2.2", ThreatType.Unknown, false,
            DateTime.UtcNow.AddDays(-5), 1)); // recent

        await _repo.DeleteOlderThanAsync(days: 30);

        var remaining = await _repo.GetAllAsync();
        remaining.Should().HaveCount(1);
        remaining[0].IpAddress.Should().Be("2.2.2.2");
    }
}