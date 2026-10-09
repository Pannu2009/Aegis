# Aegis

Server-side anti-exploit kit for Roblox. One module, drop it in, stop trusting the client.

I built this because every anti-cheat I found was either a closed black box or forum snippets that break in a week. These are patterns that actually work — remote validation, movement checks, noclip detection — all on the server where exploiters can't reach them.

## Install

**Toolbox:** search `Aegis`, insert into `ServerScriptService`.

**Manual:** one ModuleScript named `Aegis` in `ServerScriptService`, paste all of `Aegis.lua`. Done.

## Use

```lua
local Aegis = require(game.ServerScriptService.Aegis)
Aegis.init()

Aegis.secure(game.ReplicatedStorage.HitZombie, {
    args = { "number", "Instance" },
    rateLimit = { 20, 1 },
}, function(player, damage, zombie)
    -- only runs if validation passed
end)
```

Clicker game with a spammy remote? Set `rateLimit = { 200, 1 }`. Per remote, your call.

Legit teleports (spawns, portals): `Aegis.teleport(player, cframe)` — raw CFrame sets get flagged. Shots: `Aegis.reportShot(player, direction)` feeds the aimbot guard.

Weapons (infinite ammo / instant reload die here):

```lua
Aegis.registerWeapon(player, { magSize = 30, fireInterval = 0.12, reloadTime = 2 })
-- in your fire code:
if Aegis.tryFire(player) then
    -- actually fire
end
-- in your reload code:
Aegis.reloadWeapon(player)
```

Melee / kill-aura check:

```lua
if Aegis.validateHit(player, targetPosition, 12) then
    -- apply damage
end
```

Exempt staff and testers: `Aegis.trust(player)`. Tuning a new game? Start with `Aegis.init({ auditOnly = true })` — everything gets logged, nothing gets kicked, until your thresholds are dialed in.

## Config

One table at the top of the file, documented in the index header. The knobs you'll actually touch: `kickOnDetect`, `flagThreshold`, per-remote `rateLimit`, `movement.baseSpeed`. Aimbot guard is flag-only on purpose — good players look suspicious to bad heuristics.

## Inside

- **RemoteValidator** — arg types, rate limits, oversized payloads (the stuff that crashes servers)
- **MovementGuard** — displacement-based. Speed, teleport, TweenService, PivotTo — all move the character, one check catches them
- **NoclipGuard** — path raycasts + inside-geometry checks
- **AimbotGuard** — snap detection, tracking consistency, flag-only
- **CombatGuard** — server-side ammo, fire-rate, reload timers, trigger-bot consistency (warn-only)
- **HitValidator** — kill-aura range checks
- **SessionGuard** — server-side AFK tracking (server kicks can't be hooked by anti-kick)
- **InventoryGuard** — atomic give/take/trade with per-player locks, persisted to DataStore on every mutation. Script dupes die on the lock; wifi-freeze dupes die on the immediate save
- **ShopGuard** — server-side catalog prices, balance-checked buys. Purchase bypasses die here
- **BehaviorGuard** — farm-bot detection: metronome timing + marathon sessions (warn-only)
- **Logger** — strikes, kicks, optional Discord webhook

Physics-based checks (movement, noclip, remotes, hits) can't false-positive on skill — a pro player doesn't move faster than physics allows. Only the statistical heuristics (aimbot, fire consistency) can look suspicious, and those never kick, only log.

## Updates

**2026-10-09 ~12:05 PDT** — v0.2: InventoryGuard (dupe-proof atomic transactions), ShopGuard (server-side prices), BehaviorGuard (auto-farm detection)
**2026-10-09 ~11:50 PDT** — CombatGuard, HitValidator, SessionGuard. Trust list, audit mode, strike thresholds
**2026-10-09 ~11:35 PDT** — Single-file edition. Index-only header, no inline comments. README rewritten
**2026-10-09 ~11:20 PDT** — First release: RemoteValidator, MovementGuard, NoclipGuard, AimbotGuard

## License

MIT. Do what you want with it.

---
**Dakait** — [dakait.lol](https://dakait.lol)

I also build [Dakarún](https://dakait.lol), a Lua obfuscator for Roblox scripts.
