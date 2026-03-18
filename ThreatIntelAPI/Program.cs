using Microsoft.EntityFrameworkCore;
using Scalar.AspNetCore;
using ThreatIntelAPI.Application.Services;
using ThreatIntelAPI.Configuration;
using ThreatIntelAPI.Domain.Interfaces;
using ThreatIntelAPI.Infrastructure.Factories;
using ThreatIntelAPI.Infrastructure.Persistence;
using ThreatIntelAPI.Infrastructure.Repositories;

var builder = WebApplication.CreateBuilder(args);

// Configuration
var scannerConfig = builder.Configuration.GetSection("ThreatScanner").Get<ScannerConfiguration>() ??
                    new ScannerConfiguration();

builder.Services.AddSingleton(scannerConfig);

// Infra
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("Default")));

builder.Services.AddScoped<IThreatRepository, PostgresThreatRepository>();
builder.Services.AddHttpClient();
builder.Services.AddMemoryCache();

//Scanners
builder.Services.AddScoped<ThreatScannerFactory>();
builder.Services.AddScoped<IEnumerable<IThreatScanner>>(provider =>
{
    var factory = provider.GetRequiredService<ThreatScannerFactory>();
    return factory.CreateAll();
});

//Application
builder.Services.AddScoped<ThreatService>();

//api
builder.Services.AddControllers();
builder.Services.AddOpenApi();

var app = builder.Build();

//Migrate at startup
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.Migrate();
}


app.MapOpenApi();
app.MapScalarApiReference();

app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();

app.Run();