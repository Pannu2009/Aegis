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

## Config

One table at the top of the file, documented in the index header. The knobs you'll actually touch: `kickOnDetect`, `flagThreshold`, per-remote `rateLimit`, `movement.baseSpeed`. Aimbot guard is flag-only on purpose — good players look suspicious to bad heuristics.

## Inside

- **RemoteValidator** — arg types, rate limits, oversized payloads (the stuff that crashes servers)
- **MovementGuard** — displacement-based. Speed, teleport, TweenService, PivotTo — all move the character, one check catches them
- **NoclipGuard** — path raycasts + inside-geometry checks
- **AimbotGuard** — snap detection, tracking consistency, flag-only
- **Logger** — strikes, kicks, optional Discord webhook

## License

MIT. Do what you want with it.

---
**Dakait** — [dakait.lol](https://dakait.lol)

I also build [Dakarún](https://dakait.lol), a Lua obfuscator for Roblox scripts.
