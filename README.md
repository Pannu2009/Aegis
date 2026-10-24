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

Note: AFK pings fire on every validated remote call. If your game has no secured remotes, call `Aegis.ping(player)` in your game loop — otherwise active players get AFK-kicked.

## Config

One table at the top of the file, documented in the index header. The knobs you'll actually touch: `kickOnDetect`, `flagThreshold`, per-remote `rateLimit`, `movement.baseSpeed`. Aimbot guard is flag-only on purpose — good players look suspicious to bad heuristics.

## Inside

- **RemoteValidator** — arg types (including optional `"Vector3?"` args), rate limits per remote AND a global per-player budget, oversized payloads, and deep finiteness checks: a NaN passes a type check but fails every range check downstream, so non-finite numbers/Vectors/CFrames are rejected at the door
- **MovementGuard** — displacement-based. Speed, teleport, TweenService, PivotTo — all move the character, one check catches them
- **NoclipGuard** — path raycasts + inside-geometry checks
- **AimbotGuard** — snap detection, tracking consistency, flag-only
- **CombatGuard** — server-side ammo, fire-rate, reload timers, trigger-bot consistency (warn-only)
- **HitValidator** — kill-aura range checks
- **SessionGuard** — server-side AFK tracking (server kicks can't be hooked by anti-kick)
- **InventoryGuard** — atomic give/take/trade with per-player locks (single-server), persisted to DataStore on every mutation. All amounts and stored values are sanitized — NaN/inf/poisoned counts can never enter or survive. Script dupes die on the lock; wifi-freeze dupes die on the immediate save
- **ShopGuard** — server-side catalog prices, balance-checked buys. Purchase bypasses die here
- **BehaviorGuard** — farm-bot detection: metronome timing + marathon sessions (warn-only)
- **Logger** — strikes (with decay, so old flags fade), kicks, Discord webhook with event-only posting + rate guard
- **HoneypotGuard** — decoy remotes (`GiveAdmin`, `FreeRewards`, ...) no legit client ever fires. Any call is a certain flag, zero false positives
- **BanGuard** — opt-in timed bans with expiry, persisted in a DataStore, checked on join
- **sanitizeData** — deep-clean values before DataStore saves; one NaN leaf can't fail the whole save anymore

Physics-based checks (movement, noclip, remotes, hits) can't false-positive on skill — a pro player doesn't move faster than physics allows. Only the statistical heuristics (aimbot, fire consistency) can look suspicious, and those never kick, only log.

## Updates

**2026-10-23** — v0.4: HoneypotGuard decoy remotes, BanGuard timed bans (opt-in), global remote rate budget, strike decay, `Aegis.sanitizeData`. v0.3 (same day): finiteness validation in the remote validator, inventory sanitization, webhook event posting + rate guard, rate-bucket cleanup

**2026-10-09 ~12:20 PDT** — secureFunction: RemoteFunction validation (dogfooding in Pumpkin Defense)
**2026-10-09 ~12:15 PDT** — Fixed negative-amount item duplication in inventory API, combat enabled flag
**2026-10-09 ~12:00 PDT** — Fixed respawn false-positive in movement/noclip guards
**2026-10-09 ~11:55 PDT** — v0.2: InventoryGuard (dupe-proof atomic transactions), ShopGuard (server-side prices), BehaviorGuard (auto-farm detection)
**2026-10-09 ~11:50 PDT** — CombatGuard, HitValidator, SessionGuard. Trust list, audit mode, strike thresholds
**2026-10-09 ~11:20 PDT** — First release: RemoteValidator, MovementGuard, NoclipGuard, AimbotGuard

## License

MIT. Do what you want with it.

---
**Dakait** — [dakait.lol](https://dakait.lol)

I also build [Dakarún](https://dakait.lol), a Lua obfuscator for Roblox scripts.
