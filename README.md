# <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/People/Man%20Detective.png" alt="Man Detective" width="25" height="25" /> Threat Intelligence API <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/People/Man%20Detective.png" alt="Man Detective" width="25" height="25" />



A cybersecurity-themed REST API built in C# ASP.NET Core that accepts IP addresses, assesses them against threat sources, persists results, and reacts to findings via domain events. Built as a university project to demonstrate Clean Architecture, SOLID principles, and design patterns in a real-world context.

> ![.NET](https://img.shields.io/badge/.NET_10-512BD4?style=for-the-badge&logo=dotnet&logoColor=white)
> ![C#](https://img.shields.io/badge/C%23-239120?style=for-the-badge&logo=csharp&logoColor=white)
> ![ASP.NET Core](https://img.shields.io/badge/ASP.NET_Core-512BD4?style=for-the-badge&logo=dotnet&logoColor=white)
> ![EF Core](https://img.shields.io/badge/Entity_Framework_Core-512BD4?style=for-the-badge&logo=dotnet&logoColor=white)
> ![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)
> ![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
> ![xUnit](https://img.shields.io/badge/xUnit-512BD4?style=for-the-badge&logo=dotnet&logoColor=white)

> [![Tests](https://github.com/Karzen/ThreatIntelligenceAPI/actions/workflows/tests.yml/badge.svg)](https://github.com/Karzen/ThreatIntelligenceAPI/actions/workflows/tests.yml)

---

## What it does

- Submit an IP address and get back a threat assessment (malicious/clean, severity, type)
- Results are cached — the same IP scanned within 6 hours returns the existing result without burning API quota
- Full scan history with filtering by time range and IP
- Aggregate statistics: total scans, breakdowns by type and severity, top threats
- Domain events fire when a malicious IP is found, notifying independent subscribers (audit log, metrics)
- Scanner fallback chain — VirusTotal when an API key is configured, local blocklist otherwise

---

## Quick start

**Prerequisites:** .NET 10 SDK, Docker Desktop

```bash
# Clone
git clone https://github.com/Karzen/ThreatIntelligenceAPI.git
cd ThreatIntelligenceAPI

# Start Postgres
docker compose up -d

# Run the API
cd ThreatIntelAPI
dotnet run
```

Open the API explorer at **http://localhost:5042/scalar/**

---

## API endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/threats/scan` | Submit an IP for threat assessment |
| `GET` | `/api/threats/history/{ip}` | All scans for a specific IP |
| `GET` | `/api/threats/malicious` | All malicious IPs found |
| `GET` | `/api/threats/stats` | Aggregate statistics |
| `DELETE` | `/api/threats/history/old` | Delete entries older than N days |

### Example — scan a known malicious IP

**Request:**
```http
POST /api/threats/scan
Content-Type: application/json

{
  "ipAddress": "185.220.101.45"
}
```

**Response:**
```json
{
  "ipAddress": "185.220.101.45",
  "threatType": "Malware",
  "isMalicious": true,
  "detectionCount": 1,
  "detectedAt": "2026-03-21T10:49:26.3301923Z",
  "summary": "[Malicious] 185.220.101.45 | Type: Malware | TotalDetections: 1 | DetectedAt: 3/21/2026 10:49:26 AM"
}
```

### Example — statistics

```http
GET /api/threats/stats
```

```json
{
  "totalScans": 15,
  "totalMalicious": 7,
  "byType": {
    "Malware": 3,
    "Blocklisted": 4
  },
  "topThreats": [
    "89.248.172.16",
    "185.220.101.45",
    "185.220.101.45",
    "89.248.172.16",
    "194.165.16.11"
  ]
}
```

---

## Configuration

`appsettings.json` — production (VirusTotal):
```json
{
  "ConnectionStrings": {
    "Default": "Host=localhost;Database=threatdb;Username=postgres;Password=postgres"
  },
  "ThreatScanner": {
    "Type": "VirusTotal",
    "ApiKey": "your-virustotal-api-key",
    "TimeoutMs": 5000,
    "EnableFallback": true,
    "BlocklistIPs": []
  }
}
```

`appsettings.Development.json` — local dev (no API key needed):
```json
{
  "ThreatScanner": {
    "Type": "LocalBlocklist",
    "EnableFallback": false
  }
}
```

The API auto-migrates the database on startup — no manual `dotnet ef database update` needed.

---

## Architecture

This project follows **[Clean Architecture](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)** — dependencies point inward only. The domain layer has zero knowledge of databases, HTTP clients, or frameworks.

![Architecture light](docs/architecture-light.svg#gh-light-mode-only)
![Architecture dark](docs/architecture-dark.svg#gh-dark-mode-only)



---

## Design patterns

### Strategy
`ThreatService` holds an ordered list of `IThreatScanner` implementations. At scan time it picks the first available one. VirusTotal is tried first; the local blocklist is the fallback. Adding a new scanner provider requires zero changes to `ThreatService`.

### Decorator
Caching and logging are added to the scanner stack without modifying `VirusTotalScanner`. The decorator chain is: `CachingScanner -> LoggingScanner -> VirusTotalScanner`. `ThreatService` holds the outermost layer and has no knowledge of the stack.

### Repository
`ThreatService` calls methods like `WasRecentlyScannedAsync` and `GetMaliciousAsync`. It has no idea whether data comes from Postgres, SQLite, or a mock. Swapping the database means writing one new class and one registration line.

### Factory
`ThreatScannerFactory` uses a dictionary of factory functions keyed by scanner type name. Adding a new scanner type is one entry in the dictionary.

```csharp
_builders = new Dictionary<string, Func<IThreatScanner>>(StringComparer.OrdinalIgnoreCase)
{
    ["VirusTotal"]    = CreateVirusTotal,
    ["LocalBlocklist"] = CreateLocalBlocklist,
};
```

### Observer — domain events
When a malicious IP is detected, `ThreatService` fires a `ThreatDetected` event. Subscribers (audit logger, metrics tracker) react independently. Adding a new reaction — Slack notification, webhook — means writing one new subscriber class. `ThreatService` never changes.

---

## Running the tests

```bash
cd ThreatIntelAPI.Tests
dotnet test --verbosity normal
```

27 tests covering three layers:

```
ThreatEntryTests      -> domain model validation, methods
ThreatServiceTests    -> scan flow, cache hits, observer events, scanner fallback
RepositoryTests       -> all 8 repository methods against EF Core in-memory DB
```

Tests use `Moq` for mocking and `FluentAssertions` for readable assertions. The repository tests use EF Core's in-memory provider.

