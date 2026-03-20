using FluentAssertions;
using ThreatIntelAPI.Domain.Models;
using Xunit;


namespace ThreatIntelAPI.Tests;

public class ThreatEntryTests
{
    [Fact]
    public void Constructor_ThrowsArgumentException_WhenIpIsEmpty()
    {
        var act = () => new ThreatEntry("", ThreatType.Malware, true);
        act.Should().Throw<ArgumentException>();
    }


    [Fact]
    public void Constructor_ThrowsArgumentException_WhenIpIsInvalid()
    {
        var act = () => new ThreatEntry("not-an-ip", ThreatType.Malware, true);
        act.Should().Throw<ArgumentException>()
            .WithMessage("*not a valid IP*");
    }

    [Xunit.Theory]
    [InlineData("192.168.1.1")]
    [InlineData("8.8.8.8")]
    [InlineData("2001:db8::1")]
    public void IsValidIp_ReturnsTrue_ForValidAddresses(string ip)
    {
        ThreatEntry.IsValidIp(ip).Should().BeTrue();
    }

    [Xunit.Theory]
    [InlineData("not-an-ip")]
    [InlineData("")]
    [InlineData("999.999.999.999")]
    public void IsValidIp_ReturnsFalse_ForInvalidAddresses(string ip)
    {
        ThreatEntry.IsValidIp(ip).Should().BeFalse();
    }


    [Xunit.Theory]
    [InlineData("192.168.1.1")]
    [InlineData("8.8.8.8")]
    [InlineData("185.220.101.45")]
    [InlineData("2001:db8::1")] // IPv6
    public void Constructor_Succeeds_WithValidIp(string ip)
    {
        var act = () => new ThreatEntry(ip, ThreatType.Unknown, false);
        act.Should().NotThrow();
    }

    [Fact]
    public void IncrementDetection_IncreasesCountByOne()
    {
        var entry = new ThreatEntry("1.2.3.4", ThreatType.Malware, true);
        entry.DetectionCount.Should().Be(1);

        entry.IncrementDetection();

        entry.DetectionCount.Should().Be(2);
    }

    [Fact]
    public void IsRecent_ReturnsTrue_WhenDetectedWithinWindow()
    {
        var entry = new ThreatEntry(
            "1.2.3.4", ThreatType.Malware, true,
            DateTime.UtcNow.AddHours(-2), 1);

        entry.IsRecent(6).Should().BeTrue();
    }

    [Fact]
    public void IsRecent_ReturnsFalse_WhenDetectedOutsideWindow()
    {
        var entry = new ThreatEntry(
            "1.2.3.4", ThreatType.Malware, true,
            DateTime.UtcNow.AddHours(-10), 1);

        entry.IsRecent(6).Should().BeFalse();
    }
}