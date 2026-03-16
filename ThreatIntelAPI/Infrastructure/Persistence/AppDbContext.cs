using Microsoft.EntityFrameworkCore;

namespace ThreatIntelAPI.Infrastructure.Persistence;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<ThreatEntryEntity> Threats { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Override EF Core conventions
        modelBuilder.Entity<ThreatEntryEntity>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.IpAddress).IsRequired().HasMaxLength(45);
                entity.Property(e => e.ThreatType).IsRequired().HasMaxLength(50);
                entity.Property(e => e.DetectedAt).IsRequired();
                entity.HasIndex(e => e.IpAddress).HasDatabaseName("ix_threats_ip");
                entity.HasIndex(e => new { e.IpAddress, e.DetectedAt }).HasDatabaseName("ix_threats_ip_date");
                entity.HasIndex(e => e.IsMalicious).HasDatabaseName("ix_threats_malicious");
                entity.ToTable("threats");
            }
        );
    }
}