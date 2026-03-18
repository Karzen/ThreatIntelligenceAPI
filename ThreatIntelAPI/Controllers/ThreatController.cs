using Microsoft.AspNetCore.Mvc;
using ThreatIntelAPI.Application.Services;
using ThreatIntelAPI.Domain.Models;

namespace ThreatIntelAPI.Controllers;

[ApiController]
[Route("api/threats")]
public class ThreatController : ControllerBase
{
    private readonly ThreatService _threatService;
    private readonly ILogger<ThreatController> _logger;

    public ThreatController(ThreatService threatService, ILogger<ThreatController> logger)
    {
        _threatService = threatService;
        _logger = logger;
    }

    [HttpPost("scan")]
    [ProducesResponseType(typeof(ScanResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status503ServiceUnavailable)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Scan([FromBody] ScanRequest request)
    {
        if (!ThreatEntry.IsValidIp(request.IpAddress))
            return BadRequest(new ErrorResponse($"{request.IpAddress} is not a valid IP address"));

        try
        {
            var entry = await _threatService.CheckIpAsync(request.IpAddress);
            return Ok(ScanResponse.From(entry));
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogError(ex, $"Scan Failed for {request.IpAddress}");
            return StatusCode(503, new ErrorResponse(ex.Message));
        }
        
    }

    [HttpGet("history")]
    [ProducesResponseType(typeof(List<ScanResponse>), StatusCodes.Status200OK)]   
    public async Task<IActionResult> GetHistory([FromQuery] int hours = 24)
    {
        var entries = await _threatService.GetHistoryAsync(hours);
        return Ok(entries.Select(ScanResponse.From));
    }

    [HttpGet("malicious")]
    [ProducesResponseType(typeof(List<ScanResponse>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetMalicious()
    {
        var entries = await _threatService.GetMaliciousAsync();
        return Ok(entries.Select(ScanResponse.From));
    }

    [HttpGet("Stats")]
    [ProducesResponseType(typeof(ThreatStatsDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetStatus()
    {
        var stats = await _threatService.GetStatsAsync();
        return Ok(stats);
    }

    [HttpDelete("history/old")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Cleanup([FromQuery] int days = 30)
    {
        await _threatService.CleanupAsync(days);
        return NoContent();   
    }


}