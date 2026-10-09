--// =====================================================================
--// Aegis v0.1 — open-source anti-exploit kit for Roblox games.
--//
--// SINGLE-FILE EDITION. Drop this entire file into ONE ModuleScript
--// named "Aegis" in ServerScriptService. No child modules needed.
--//
--//   local Aegis = require(game.ServerScriptService.Aegis)
--//   Aegis.init()
--//   Aegis.secure(remote, { args = {"number"} }, handler)
--//
--// Built by Arzh. https://github.com/Pannu2009/Aegis
--// MIT License.
--// =====================================================================

local Players = game:GetService("Players")
local Workspace = game:GetService("Workspace")
local HttpService = game:GetService("HttpService")

local Aegis = {}

--// ============================== CONFIG ==============================

local Config = {
	kickOnDetect = true,
	flagThreshold = 3, -- strikes in a category before auto-kick
	discordWebhook = "", -- optional: flags/kicks posted here

	-- Defaults applied to every secured remote unless overridden.
	remoteDefaults = {
		rateLimit = { 20, 1 }, -- 20 calls per second per player
		maxArgSize = 2048, -- max string length / table entries per arg
	},

	-- Per-remote overrides, keyed by RemoteEvent name.
	-- Example (clicker game with a high-frequency remote):
	--   remotes = {
	--     ClickButton = { rateLimit = { 200, 1 } },
	--     BuyItem     = { args = { "string", "number" }, rateLimit = { 5, 1 } },
	--   },
	remotes = {},

	-- Catches speed hacks, teleports, TweenService and PivotTo abuse.
	-- All movement methods change position; displacement catches them all.
	movement = {
		enabled = true,
		baseSpeed = 16, -- studs/sec; raise for games with faster movement
		tolerance = 1.3, -- multiplier for lag compensation
		checkInterval = 0.2,
		ignoreSeated = true, -- skip players in vehicles/seats
	},

	-- Catches noclip via path raycasts + inside-geometry checks.
	noclip = {
		enabled = true,
		checkInterval = 0.5,
		ignoreSeated = true,
	},

	-- Statistical aimbot detection. Flag-only by design: good players
	-- look suspicious to naive heuristics.
	aimbot = {
		enabled = true,
		maxSnapDegrees = 100, -- max aim-angle change between consecutive shots
		flagOnly = true, -- never auto-kick; log + flag for review
	},
}

--// ============================== LOGGER ==============================
-- Flags, strikes, kicks, optional Discord webhook.

local Logger = {}
local strikes = {} -- ["userId:category"] = count

local function sendWebhook(message)
	if Config.discordWebhook == "" then
		return
	end
	task.spawn(function()
		pcall(function()
			HttpService:PostAsync(
				Config.discordWebhook,
				HttpService:JSONEncode({ content = "[Aegis] " .. message })
			)
		end)
	end)
end

function Logger.log(message)
	print("[Aegis] " .. message)
	sendWebhook(message)
end

-- Records a strike. Kicks when the category hits flagThreshold.
function Logger.flag(player, category, detail)
	local key = player.UserId .. ":" .. category
	strikes[key] = (strikes[key] or 0) + 1
	local count = strikes[key]
	Logger.log(string.format(
		"FLAG %s (%d) [%s] %s (strike %d)",
		player.Name,
		player.UserId,
		category,
		detail or "",
		count
	))
	if Config.kickOnDetect and count >= Config.flagThreshold then
		Logger.kick(player, "Aegis: " .. category)
	end
	return count
end

-- Log-only, no strike. Used by heuristic guards (aimbot) to avoid
-- punishing legitimately skilled players.
function Logger.warn(player, category, detail)
	Logger.log(string.format(
		"WARN %s (%d) [%s] %s",
		player.Name,
		player.UserId,
		category,
		detail or ""
	))
end

function Logger.kick(player, reason)
	Logger.log("KICK " .. player.Name .. " (" .. player.UserId .. ") — " .. reason)
	player:Kick(reason)
end

function Logger.clear(player)
	local prefix = player.UserId .. ":"
	for k in pairs(strikes) do
		if k:sub(1, #prefix) == prefix then
			strikes[k] = nil
		end
	end
end

--// ============================ AIMBOT GUARD ============================
-- Statistical detection. Two heuristics:
--   1. Snap: impossible angle change between consecutive shots.
--   2. Lock: inhuman tracking consistency over many shots.
-- Flag-only BY DESIGN. Feed via Aegis.reportShot(player, aimDirection),
-- or set trackAim in a secured remote's schema to auto-feed a Vector3 arg.

local AimbotGuard = {}
local aimHistory = {} -- [userId] = { {dir = Vector3, t = number}, ... }
local MAX_AIM_HISTORY = 30

local function angleBetween(a, b)
	return math.deg(math.acos(math.clamp(a:Dot(b), -1, 1)))
end

function AimbotGuard.trackShot(player, aimDir)
	if not Config.aimbot.enabled then
		return
	end
	if typeof(aimDir) ~= "Vector3" or aimDir.Magnitude < 0.001 then
		return
	end

	local uid = player.UserId
	local h = aimHistory[uid]
	if not h then
		h = {}
		aimHistory[uid] = h
	end

	local now = os.clock()
	local dir = aimDir.Unit

	if #h > 0 then
		local prev = h[#h]
		local snap = angleBetween(prev.dir, dir)
		if snap > Config.aimbot.maxSnapDegrees and (now - prev.t) < 1 then
			Logger.warn(
				player,
				"aimbot",
				string.format("snap %.0f deg in %.2fs", snap, now - prev.t)
			)
		end
	end

	table.insert(h, { dir = dir, t = now })
	if #h > MAX_AIM_HISTORY then
		table.remove(h, 1)
	end

	-- Inhuman steadiness: 10 consecutive shot pairs all under 1.5 degrees
	-- apart while firing means the aim is not driven by a human hand.
	if #h >= 11 then
		local steady = 0
		for i = #h - 9, #h do
			if angleBetween(h[i - 1].dir, h[i].dir) < 1.5 then
				steady += 1
			end
		end
		if steady >= 10 then
			Logger.warn(player, "aimbot", "inhuman tracking consistency")
			aimHistory[uid] = {}
		end
	end
end

--// ========================== REMOTE VALIDATOR ==========================
-- Validates RemoteEvent traffic server-side: arg types, per-player rate
-- limits, arg size caps (anti-crasher). Invalid calls never reach game logic.

local RemoteValidator = {}
local rateBuckets = {} -- ["userId\0RemoteName"] = { timestamps }

local function typeOk(value, expected)
	if expected == "any" then
		return true
	end
	return typeof(value) == expected
end

local function sizeOk(value, maxSize)
	if typeof(value) == "string" then
		return #value <= maxSize
	elseif typeof(value) == "table" then
		local n = 0
		for _ in pairs(value) do
			n += 1
			if n > maxSize then
				return false
			end
		end
	end
	return true
end

local function rateOk(player, remoteName, limit)
	local maxCalls, perSec = limit[1], limit[2]
	local key = player.UserId .. "\0" .. remoteName
	local now = os.clock()
	local kept = {}
	for _, t in ipairs(rateBuckets[key] or {}) do
		if now - t < perSec then
			table.insert(kept, t)
		end
	end
	rateBuckets[key] = kept
	if #kept >= maxCalls then
		return false
	end
	table.insert(kept, now)
	return true
end

local function resolveSchema(remote, override)
	local schema = {
		args = {},
		rateLimit = Config.remoteDefaults.rateLimit,
		maxArgSize = Config.remoteDefaults.maxArgSize,
		trackAim = false,
		aimArg = 1,
	}
	local per = Config.remotes[remote.Name]
	if per then
		for k, v in pairs(per) do
			schema[k] = v
		end
	end
	if override then
		for k, v in pairs(override) do
			schema[k] = v
		end
	end
	return schema
end

-- secure(remote, schema?, handler)
function RemoteValidator.secure(remote, schemaOverride, handler)
	if typeof(schemaOverride) == "function" and handler == nil then
		handler = schemaOverride
		schemaOverride = nil
	end
	assert(typeof(handler) == "function", "Aegis.secure: handler must be a function")

	local schema = resolveSchema(remote, schemaOverride)

	remote.OnServerEvent:Connect(function(player, ...)
		local args = { ... }

		if not rateOk(player, remote.Name, schema.rateLimit) then
			Logger.flag(player, "remote-spam", remote.Name)
			return
		end

		if #args > #schema.args then
			Logger.flag(player, "remote-args", remote.Name .. ": too many args")
			return
		end

		for i, expected in ipairs(schema.args) do
			local v = args[i]
			if v == nil and expected ~= "nil" then
				Logger.flag(player, "remote-args", remote.Name .. ": missing arg " .. i)
				return
			end
			if not typeOk(v, expected) then
				Logger.flag(
					player,
					"remote-args",
					string.format(
						"%s: arg %d expected %s, got %s",
						remote.Name,
						i,
						expected,
						typeof(v)
					)
				)
				return
			end
			if not sizeOk(v, schema.maxArgSize) then
				Logger.flag(player, "remote-crasher", remote.Name .. ": oversized arg " .. i)
				return
			end
		end

		if schema.trackAim then
			local dir = args[schema.aimArg]
			if typeof(dir) == "Vector3" then
				AimbotGuard.trackShot(player, dir)
			end
		end

		local ok, err = pcall(handler, player, ...)
		if not ok then
			Logger.log("handler error in " .. remote.Name .. ": " .. tostring(err))
		end
	end)
end

--// ========================== MOVEMENT GUARD ============================
-- Server-side displacement checks. Speed hacks, teleports, TweenService
-- tweens and PivotTo calls ALL change position, so one check catches every
-- method. Legitimate scripted movement must go through Aegis.teleport().

local MovementGuard = {}
local moveLast = {} -- [userId] = Vector3
local moveExempt = {} -- [userId] = Vector3 (set by Aegis.teleport)

function MovementGuard.exempt(player, cframe)
	moveExempt[player.UserId] = cframe.Position
end

function MovementGuard.start()
	local cfg = Config.movement
	if not cfg.enabled then
		return
	end
	task.spawn(function()
		while true do
			task.wait(cfg.checkInterval)
			MovementGuard.checkAll(cfg)
		end
	end)
	Players.PlayerRemoving:Connect(function(player)
		moveLast[player.UserId] = nil
		moveExempt[player.UserId] = nil
	end)
end

function MovementGuard.checkAll(cfg)
	local dt = cfg.checkInterval
	for _, player in ipairs(Players:GetPlayers()) do
		local character = player.Character
		local hrp = character and character:FindFirstChild("HumanoidRootPart")
		local humanoid = character and character:FindFirstChildOfClass("Humanoid")
		if hrp and humanoid and humanoid.Health > 0 then
			local uid = player.UserId
			local pos = hrp.Position

			if moveExempt[uid] then
				-- Whitelisted teleport: snap the baseline, skip the check.
				moveLast[uid] = moveExempt[uid]
				moveExempt[uid] = nil
			elseif cfg.ignoreSeated and humanoid.Seated then
				moveLast[uid] = pos
			else
				local state = humanoid:GetState()
				if
					state == Enum.HumanoidStateType.Physics
					or state == Enum.HumanoidStateType.Dead
				then
					-- Game physics or death took over; not the player's doing.
					moveLast[uid] = pos
				else
					local prev = moveLast[uid]
					moveLast[uid] = pos
					if prev then
						local delta = pos - prev
						local hDist = Vector3.new(delta.X, 0, delta.Z).Magnitude
						local vDist = math.abs(delta.Y)
						local speed = humanoid.WalkSpeed
						-- Horizontal is strict; vertical gets slack for jumps/falls.
						-- Real teleports exceed both by orders of magnitude.
						local hAllowed = (speed * cfg.tolerance) * dt + 2
						local vAllowed = (speed * cfg.tolerance) * dt + 30
						if hDist > hAllowed or vDist > vAllowed then
							Logger.flag(
								player,
								"movement",
								string.format(
									"displaced h=%.1f v=%.1f in %.2fs (allowed h=%.1f v=%.1f)",
									hDist,
									vDist,
									dt,
									hAllowed,
									vAllowed
								)
							)
						end
					end
				end
			end
		end
	end
end

--// ============================ NOCLIP GUARD ============================
-- Two layers:
--   1. Path raycast: segment from last position to current. Crossing solid
--      (CanCollide) geometry means the player moved through a wall.
--   2. Inside-part check: shrunken bounding box at the character; overlap
--      with solid geometry means the player is embedded in a wall.
-- Floor-like hits (normal pointing up) are ignored: stairs aren't noclip.

local NoclipGuard = {}
local noclipLast = {} -- [userId] = Vector3
local noclipSkip = {} -- [userId] = true (set by Aegis.teleport)

function NoclipGuard.exempt(player)
	noclipSkip[player.UserId] = true
end

function NoclipGuard.start()
	local cfg = Config.noclip
	if not cfg.enabled then
		return
	end
	task.spawn(function()
		while true do
			task.wait(cfg.checkInterval)
			NoclipGuard.checkAll(cfg)
		end
	end)
	Players.PlayerRemoving:Connect(function(player)
		noclipLast[player.UserId] = nil
		noclipSkip[player.UserId] = nil
	end)
end

function NoclipGuard.checkAll(cfg)
	for _, player in ipairs(Players:GetPlayers()) do
		local character = player.Character
		local hrp = character and character:FindFirstChild("HumanoidRootPart")
		local humanoid = character and character:FindFirstChildOfClass("Humanoid")
		if hrp and humanoid and humanoid.Health > 0 then
			local uid = player.UserId
			local pos = hrp.Position

			if noclipSkip[uid] then
				noclipSkip[uid] = nil
				noclipLast[uid] = pos
			elseif cfg.ignoreSeated and humanoid.Seated then
				noclipLast[uid] = pos
			else
				local prev = noclipLast[uid]
				noclipLast[uid] = pos
				if prev and (pos - prev).Magnitude > 1 then
					local params = RaycastParams.new()
					params.FilterType = Enum.RaycastFilterType.Exclude
					params.FilterDescendantsInstances = { character }

					-- Layer 1: did the path cross solid geometry?
					local dir = pos - prev
					local hit = Workspace:Raycast(prev, dir, params)
					if hit and hit.Instance.CanCollide and hit.Normal.Y < 0.7 then
						Logger.flag(player, "noclip", "crossed " .. hit.Instance:GetFullName())
					else
						-- Layer 2: embedded inside solid geometry?
						local overlap = OverlapParams.new()
						overlap.FilterType = Enum.RaycastFilterType.Exclude
						overlap.FilterDescendantsInstances = { character }
						local parts =
							Workspace:GetPartBoundsInBox(hrp.CFrame, hrp.Size * 0.5, overlap)
						for _, part in ipairs(parts) do
							if part.CanCollide and part:IsDescendantOf(Workspace) then
								Logger.flag(player, "noclip", "inside " .. part:GetFullName())
								break
							end
						end
					end
				end
			end
		end
	end
end

--// ============================= PUBLIC API =============================

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
	MovementGuard.start()
	NoclipGuard.start()
	Logger.log("Aegis v0.1 initialized (single-file)")
	return Aegis
end

local function ensureStarted()
	if not started then
		Aegis.init()
	end
end

-- Wraps a RemoteEvent with validation. Schema fields:
--   args       = {"number", "Instance", ...}  expected arg types (typeof names, or "any")
--   rateLimit  = {maxCalls, perSeconds}       e.g. {200, 1} for clicker games
--   maxArgSize = number                        max string length / table entries (anti-crasher)
--   trackAim   = true + aimArg = 1             feed a Vector3 arg to the aimbot guard
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
