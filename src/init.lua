-- Aegis v0.1 — open-source anti-exploit kit for Roblox games.
-- Built by Arzh. https://github.com/Pannu2009/Aegis
--
-- Usage:
--   local Aegis = require(game.ServerScriptService.Aegis)
--   Aegis.init({ kickOnDetect = true })
--   Aegis.secure(remote, { args = {"number", "Instance"} }, handler)
--
-- Layout: this ModuleScript with child ModuleScripts named
-- Config, Logger, RemoteValidator, MovementGuard, NoclipGuard, AimbotGuard.

local Aegis = {}

local Config = require(script.Config)
local Logger = require(script.Logger)
local RemoteValidator = require(script.RemoteValidator)
local MovementGuard = require(script.MovementGuard)
local NoclipGuard = require(script.NoclipGuard)
local AimbotGuard = require(script.AimbotGuard)

local started = false

local function deepMerge(dst, src)
	for k, v in pairs(src) do
		if typeof(v) == "table" and typeof(dst[k]) == "table" then
			deepMerge(dst[k], v)
		else
			dst[k] = v
		end
	end
end

function Aegis.configure(overrides)
	deepMerge(Config, overrides or {})
	return Aegis
end

function Aegis.init(options)
	if started then
		return Aegis
	end
	started = true
	Aegis.configure(options)
	Logger.init(Config)
	RemoteValidator.init(Config, Logger)
	MovementGuard.init(Config, Logger)
	NoclipGuard.init(Config, Logger)
	AimbotGuard.init(Config, Logger)
	Logger.log("Aegis v0.1 initialized")
	return Aegis
end

local function ensureStarted()
	if not started then
		Aegis.init()
	end
end

-- Wraps a RemoteEvent with validation. Schema fields:
--   args      = {"number", "Instance", ...}  expected arg types (typeof names, or "any")
--   rateLimit = {maxCalls, perSeconds}       e.g. {200, 1} for clicker games
--   maxArgSize= number                        max string length / table entries (anti-crasher)
--   trackAim  = true + aimArg = 1             feed a Vector3 arg to the aimbot guard
function Aegis.secure(remote, schema, handler)
	ensureStarted()
	return RemoteValidator.secure(remote, schema, handler)
end

-- Whitelist a legitimate teleport so the movement/noclip guards ignore it.
-- Call this INSTEAD of setting CFrame directly for spawns, portals, etc.
function Aegis.teleport(player, cframe)
	ensureStarted()
	MovementGuard.exempt(player, cframe)
	NoclipGuard.exempt(player)
	local hrp = player.Character and player.Character:FindFirstChild("HumanoidRootPart")
	if hrp then
		hrp.CFrame = cframe
	end
end

-- Feed a shot's aim direction to the aimbot guard. Call from your weapon code.
function Aegis.reportShot(player, aimDirection)
	ensureStarted()
	AimbotGuard.trackShot(player, aimDirection)
end

Aegis.Config = Config
Aegis.Logger = Logger

return Aegis
