using Microsoft.EntityFrameworkCore;
using ThreatIntelAPI.Domain.Interfaces;
using ThreatIntelAPI.Domain.Models;
using ThreatIntelAPI.Infrastructure.Persistence;

namespace ThreatIntelAPI.Infrastructure.Repositories;

public class PostgresThreatRepository : IThreatRepository
{
    private readonly AppDbContext _context;

    public PostgresThreatRepository(AppDbContext context)
    {
        _context = context;
    }

    public async Task SaveAsync(ThreatEntry entry)
    {
        var entity = MapToEntity(entry);
        _context.Threats.Add(entity);
        await _context.SaveChangesAsync();
    }

    public async Task<ThreatEntry?> FindByIpAsync(string ipAddress)
    {
        var entity = await _context.Threats.Where(t => t.IpAddress == ipAddress).OrderByDescending(t => t.DetectedAt).FirstOrDefaultAsync();
        return entity is null ? null : MapToDomain(entity);
    }

    public async Task<List<ThreatEntry>> GetAllAsync()
    {
        var entities = await _context.Threats.OrderByDescending(t => t.DetectedAt).ToListAsync();
        return entities.Select(MapToDomain).ToList();
    }

    public async Task<List<ThreatEntry>> GetRecentAsync(int hours = 24)
    {
        var until = DateTime.UtcNow.AddHours(-hours);

        var entities = await _context.Threats.Where(t => t.DetectedAt >= until).OrderByDescending(t => t.DetectedAt)
            .ToListAsync();
        return entities.Select(MapToDomain).ToList();
    }

    public async Task<List<ThreatEntry>> GetMaliciousAsync()
    {
        var entities = await _context.Threats.Where(t => t.IsMalicious).OrderByDescending(t => t.DetectedAt)
            .ToListAsync();
        return entities.Select(MapToDomain).ToList();
    }

    public async Task<bool> WasRecentlyScannedAsync(string ipAddress, int withinHours = 6)
    {
        var until = DateTime.UtcNow.AddHours(-withinHours);
        return await _context.Threats.AnyAsync(t => t.IpAddress == ipAddress && t.DetectedAt >= until);
    }

    public async Task<int> GetTotalScanCountAsync()
    {
        return await _context.Threats.CountAsync();
    }

    public async Task IncrementDetectionCountAsync(string ipAddress)
    {
        var entity = await _context.Threats.Where(t => t.IpAddress == ipAddress).OrderByDescending(t => t.DetectedAt)
            .FirstOrDefaultAsync();

        if (entity is null) return;
        entity.DetectionCount++;
        await _context.SaveChangesAsync();
    }

    public async Task DeleteOlderThanAsync(int days)
    {
        var until = DateTime.UtcNow.AddDays(-days);
        var old = await _context.Threats.Where(t => t.DetectedAt < until).ToListAsync();

        if (!old.Any()) return;
        
        _context.Threats.RemoveRange(old);
        await _context.SaveChangesAsync();
    }

    private ThreatEntryEntity MapToEntity(ThreatEntry entry) => new()
    {
        IpAddress = entry.IpAddress,
        ThreatType = entry.Type.ToString(),
        DetectedAt = entry.DetectedAt,
        IsMalicious = entry.IsMalicious,
        DetectionCount = entry.DetectionCount
    };

    private ThreatEntry MapToDomain(ThreatEntryEntity entity)
    {
        var type = Enum.Parse<ThreatType>(entity.ThreatType);
        return new ThreatEntry(entity.IpAddress, type, entity.IsMalicious, entity.DetectedAt, entity.DetectionCount);
    }
}