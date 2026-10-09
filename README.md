# Aegis

Open-source anti-exploit kit for Roblox games. Server-side validation for remotes, movement, noclip, and aimbots — drop it in, configure it, stop trusting the client.

Built by [Arzh](https://dakait.lol/portfolio). Battle-tested patterns from real anti-exploit work shipping in live games.

## Why

Most Roblox exploit defenses are either closed-source black boxes or scattered forum snippets. Aegis is neither: every line is readable, every check runs on the server where exploiters can't touch it, and integration takes five minutes.

Core principle: **never trust the client.** Validate everything on the server.

## Install

**Option A — Creator Store (easiest):** search `Aegis` in the Toolbox, insert into `ServerScriptService`.

**Option B — GitHub:** create a ModuleScript named `Aegis` in `ServerScriptService`, paste `src/init.lua`, then create child ModuleScripts named `Config`, `Logger`, `RemoteValidator`, `MovementGuard`, `NoclipGuard`, `AimbotGuard` and paste each matching file.

## Quickstart

```lua
local Aegis = require(game.ServerScriptService.Aegis)

Aegis.init({
    kickOnDetect = true,
    discordWebhook = "YOUR_WEBHOOK", -- optional: flags/kicks posted here
})

-- Wrap a RemoteEvent with validation. Invalid calls never reach your logic.
Aegis.secure(game.ReplicatedStorage.HitZombie, {
    args = { "number", "Instance" }, -- expected arg types
    rateLimit = { 20, 1 },            -- max 20 calls/sec per player
}, function(player, damage, zombie)
    -- your handler
end)

-- Clicker game with a high-frequency remote? Crank the limit.
Aegis.secure(game.ReplicatedStorage.Click, {
    args = {},
    rateLimit = { 200, 1 },
}, function(player)
    -- your handler
end)

-- Legitimate teleports (spawns, portals) go through Aegis, not raw CFrame sets.
Aegis.teleport(player, CFrame.new(0, 10, 0))

-- Feed shots to the aimbot guard from your weapon code.
Aegis.reportShot(player, aimDirection)
```

Or set per-remote rules centrally:

```lua
Aegis.configure({
    remotes = {
        ClickButton = { rateLimit = { 200, 1 } },
        BuyItem = { args = { "string", "number" }, rateLimit = { 5, 1 } },
    },
    movement = { baseSpeed = 24 }, -- your game is faster than default
})
```

## Modules

| Module | Catches |
|---|---|
| `RemoteValidator` | Remote spam, malformed args, oversized payloads (server crashers), type confusion |
| `MovementGuard` | Speed hacks, teleports, TweenService abuse, PivotTo abuse — displacement-based, so the method doesn't matter |
| `NoclipGuard` | Noclip via path raycasts + inside-geometry checks |
| `AimbotGuard` | Aim snap + inhuman tracking consistency (flag-only by design — good players look suspicious) |
| `Logger` | Strikes, kicks, Discord webhook alerts |

## Configuration

All defaults live in `Config.lua`. Key knobs:

- `kickOnDetect` / `flagThreshold` — kick after N strikes in a category
- `remoteDefaults.rateLimit` / `maxArgSize` — global remote policy
- `remotes` — per-RemoteEvent overrides (the clicker-game case)
- `movement.baseSpeed` / `tolerance` — tune to your game's movement
- `aimbot.flagOnly` — keep `true`; statistical detection should never auto-kick

## Roadmap

- **v0.2** — `CombatGuard` (server-authoritative ammo, fire-rate, reload timing, trigger-bot heuristics), `HitValidator` (kill-aura distance checks, canonical hitbox sizes), `SessionGuard` (server-side kicks that anti-kick can't block, server-side AFK tracking)
- **v0.3** — `InventoryGuard` (dupe-proof server-authoritative transactions), `ShopGuard` (server-side prices and balances — purchase bypasses die here), `BehaviorGuard` (auto-farm timing heuristics)
- **Guides** — replication hygiene vs. instance-tree scraping (what you can't stop, what you can starve)

## Contributing

PRs welcome. Keep modules under 1,000 lines, server-side only, no trust in the client — ever.

## License

MIT. See `LICENSE`.
