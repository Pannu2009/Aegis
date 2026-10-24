--// Aegis v0.5 — open-source anti-exploit kit for Roblox games.
--// One ModuleScript in ServerScriptService. MIT License.
--// Built by Dakait — https://dakait.lol
--//
--// INDEX (top to bottom):
--//   Config ........... kick policy, audit mode, remote defaults,
--//                      per-remote overrides, guard tuning, presets
--//   Logger ........... flag() strikes + escalation ladder + cross-server
--//                      strikes, warn() log-only, kick(), discord webhook
--//                      (embeds + digest mode), evidence snapshots
--//   Trust ............ Aegis.trust(): exempt staff/testers from all guards
--//   AimbotGuard ...... trackShot(): snap angles + tracking consistency, flag-only
--//   SessionGuard ..... server-side AFK tracking (server kicks can't be hooked)
--//   RemoteValidator .. secure()/secureFunction(): arg types, rate limits,
--//                      arg size caps (events + functions)
--//   MovementGuard .... displacement checks: speed, teleport, tween, pivot
--//   NoclipGuard ...... path raycasts + inside-geometry checks
--//   CombatGuard ...... registerWeapon/tryFire/reloadWeapon: server-side ammo,
--//                      fire-rate, reload timers, trigger-bot check (warn-only)
--//   HitValidator ..... validateHit(): kill-aura range checks
--//   InventoryGuard ... give/take/trade: atomic, locked, persisted on every
--//                      mutation (kills script dupes + wifi-freeze dupes),
--//                      honeypot items (possession = certain exploit)
--//   ShopGuard ........ server-side catalog prices, balance-checked buys,
--//                      idempotent receipts (replayed buys grant once)
--//   BehaviorGuard .... recordAction(): farm-bot timing + marathon heuristics
--//                      + adaptive baselines (machine-consistent timing)
--//   ClientCompanion .. optional LocalScript tripwire (ping presence;
--//                      NEVER sole evidence -- exploiters can delete it)
--//   SelfTest ......... dev-only guard verification (Studio command bar)
--//   Public API ....... init / configure / preset / secure / secureFunction / teleport /
--//                      reportShot / trust / untrust / registerWeapon / tryFire /
--//                      reloadWeapon / validateHit / ping / giveItem / takeItem /
--//                      tradeItems / hasItem / setShop / buyItem / recordAction /
--//                      validInstance / addHoneypotItem / getClientStatus /
--//                      flushDigest / selfTest
--//
--// Install: paste this whole file into a ModuleScript named "Aegis".
--// Usage:
--//   local Aegis = require(game.ServerScriptService.Aegis)
--//   Aegis.init()
--//   Aegis.secure(remote, { args = {"number"} }, function(player, ...) end)

local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local DataStoreService = game:GetService("DataStoreService")
local MemoryStoreService = game:GetService("MemoryStoreService")
local Workspace = game:GetService("Workspace")
local HttpService = game:GetService("HttpService")

local Aegis = {}

--// CONFIG

local Config = {
	kickOnDetect = true,
	flagThreshold = 3,
	discordWebhook = "",
	webhookVerbose = false,
	webhookMinInterval = 1.5,
	webhookEmbeds = true,
	webhookDigest = false,
	strikeDecaySeconds = 600,
	playerArgBinding = true,
	selfTestEnabled = false,

	globalRate = { 150, 1 },

	-- Cross-server strikes: a flag in one server counts
	-- everywhere (MemoryStore). Failures degrade to local-only.
	crossServer = {
		enabled = true,
		mapName = "aegis_strikes_v1",
		expirySeconds = 86400,
	},

	-- Escalation ladder: warn (log-only) -> kick at flagThreshold
	-- -> timed ban at banAt -> permanent ban at permAt. Ban
	-- steps stay OFF until a dev opts in (bans.enabled + these
	-- thresholds): a kit must not start banning by accident.
	escalation = {
		banAt = nil,
		banSeconds = 3600,
		permAt = nil,
	},

	honeypot = {
		enabled = true,
		names = { "GiveAdmin", "FreeRewards", "AddCoins", "GrantItem", "SetLevel" },
		items = {},
	},

	bans = {
		enabled = false,
		storeName = "aegis_bans_v1",
	},
	auditOnly = false,

	remoteDefaults = {
		rateLimit = { 20, 1 },
		maxArgSize = 2048,
	},

	remotes = {},

	movement = {
		enabled = true,
		baseSpeed = 16,
		tolerance = 1.3,
		checkInterval = 0.2,
		ignoreSeated = true,
		-- Rollback: on an impossible displacement the server
		-- snaps the player back to the last legal position
		-- (auditOnly games only ever flag -- never correct).
		rollback = true,
		-- Fly: airborne with ~zero vertical velocity (not
		-- falling, not jumping) for this long = flying.
		flySeconds = 3,
		-- Fling: horizontal physics velocity above this is no
		-- legitimate movement (falls are vertical, so they
		-- don't trip it). 0 disables the check.
		flingSpeed = 120,
	},

	noclip = {
		enabled = true,
		checkInterval = 0.5,
		ignoreSeated = true,
	},

	aimbot = {
		enabled = true,
		maxSnapDegrees = 100,
		flagOnly = true,
	},

	session = {
		enabled = true,
		maxIdle = 900,
		checkInterval = 30,
	},

	combat = {
		enabled = true,
		consistencyWindow = 10,
		consistencyTolerance = 0.05,
	},

	behavior = {
		enabled = true,
		consistencyWindow = 20,
		consistencyTolerance = 0.05,
		marathonSeconds = 21600,
		marathonActions = 500,
		breakReset = 600,
		-- Adaptive baselines: per action, the last 30 intervals
		-- are measured; a fast action with a coefficient of
		-- variation under this (machine-consistent timing) is
		-- bot-like at ANY speed, not just the metronome rate.
		adaptiveWindow = 30,
		adaptiveMaxMean = 1.0,
		adaptiveMaxCV = 0.08,
	},
}

--// LOGGER

local Logger = {}
local strikes = {}

-- Forward: BanGuard is defined below, but Logger.flag's
-- escalation ladder needs it (Lua resolves locals at
-- definition time, so this must come first).
local BanGuard

-- Recent remote calls per player, for evidence snapshots.
-- Entries are type summaries only ("BuyItem(number)"), never
-- argument values -- evidence stays small and private.
local recentCalls = {}

local function recordCall(player, remoteName, args)
	local list = recentCalls[player.UserId]
	if not list then
		list = {}
		recentCalls[player.UserId] = list
	end
	local types = {}
	for i, v in ipairs(args) do
		types[i] = typeof(v)
	end
	table.insert(list, remoteName .. "(" .. table.concat(types, ", ") .. ")")
	if #list > 10 then
		table.remove(list, 1)
	end
end

local function buildEvidence(player)
	local bits = {}
	local character = player.Character
	local hrp = character and character:FindFirstChild("HumanoidRootPart")
	if hrp then
		table.insert(bits, string.format(
			"pos (%.0f, %.0f, %.0f) vel %.0f",
			hrp.Position.X, hrp.Position.Y, hrp.Position.Z,
			hrp.AssemblyLinearVelocity.Magnitude
		))
	end
	local calls = recentCalls[player.UserId]
	if calls and #calls > 0 then
		local tail = {}
		for i = math.max(1, #calls - 4), #calls do
			table.insert(tail, calls[i])
		end
		table.insert(bits, "recent: " .. table.concat(tail, ", "))
	end
	return table.concat(bits, " | ")
end

local webhookLastPost = 0
local webhookSuppressed = 0
local digestBuffer = {}

local function severityColor(message)
	if message:sub(1, 4) == "KICK" then
		return 0xE74C3C
	end
	if message:find("honeypot") then
		return 0x9B59B6
	end
	if message:sub(1, 4) == "FLAG" then
		return 0xE67E22
	end
	return 0xF1C40F
end

local function sendWebhook(message, evidence)
	if Config.discordWebhook == "" then
		return
	end
	-- Digest mode: buffer the event instead of posting it;
	-- flushDigest() (hourly auto-flush + manual) posts the batch.
	if Config.webhookDigest then
		table.insert(digestBuffer, message)
		if #digestBuffer > 50 then
			table.remove(digestBuffer, 1)
		end
		return
	end
	local now = os.clock()
	if now - webhookLastPost < Config.webhookMinInterval then
		webhookSuppressed += 1
		return
	end
	webhookLastPost = now
	if webhookSuppressed > 0 then
		message = message .. " (+" .. webhookSuppressed .. " more suppressed)"
		webhookSuppressed = 0
	end
	local payload
	if Config.webhookEmbeds then
		local embed = {
			title = "[Aegis] event",
			color = severityColor(message),
			description = message,
		}
		if evidence and evidence ~= "" then
			embed.fields = { { name = "Evidence", value = evidence } }
		end
		payload = { embeds = { embed } }
	else
		payload = {
			content = "[Aegis] " .. message
				.. (evidence and evidence ~= "" and ("\n" .. evidence) or ""),
		}
	end
	task.spawn(function()
		pcall(function()
			HttpService:PostAsync(
				Config.discordWebhook,
				HttpService:JSONEncode(payload)
			)
		end)
	end)
end

function Logger.flushDigest()
	if #digestBuffer == 0 or Config.discordWebhook == "" then
		return
	end
	local body = table.concat(digestBuffer, "\n")
	digestBuffer = {}
	if #body > 1900 then
		body = body:sub(1, 1900)
	end
	task.spawn(function()
		pcall(function()
			HttpService:PostAsync(
				Config.discordWebhook,
				HttpService:JSONEncode({ content = "[Aegis] digest\n" .. body })
			)
		end)
	end)
end

function Logger.log(message)
	print("[Aegis] " .. message)
	if Config.webhookVerbose then
		sendWebhook(message)
	end
end

local function logEvent(message, evidence)
	print("[Aegis] " .. message)
	sendWebhook(message, evidence)
end

-- Cross-server strikes: one flag here counts everywhere.
-- Returns the cross-server total, or nil when MemoryStore is
-- unavailable (Studio, no access) -- callers fall back to the
-- local count. Never called in auditOnly mode.
local function crossServerBump(userId)
	if not Config.crossServer.enabled then
		return nil
	end
	local ok, map = pcall(function()
		return MemoryStoreService:GetSortedMap(Config.crossServer.mapName)
	end)
	if not ok or not map then
		return nil
	end
	local ok2, total = pcall(function()
		return map:UpdateAsync("strike_" .. userId, function(old)
			local n = (typeof(old) == "number" and old or 0) + 1
			return n
		end, Config.crossServer.expirySeconds)
	end)
	if ok2 and typeof(total) == "number" then
		return total
	end
	return nil
end

function Logger.flag(player, category, detail)
	local key = player.UserId .. ":" .. category
	local entry = strikes[key]
	if not entry or os.clock() - entry.last > Config.strikeDecaySeconds then
		entry = { n = 0, last = 0 }
	end
	entry.n += 1
	entry.last = os.clock()
	strikes[key] = entry
	local count = entry.n
	logEvent(string.format(
		"FLAG %s (%d) [%s] %s (strike %d)",
		player.Name,
		player.UserId,
		category,
		detail or "",
		count
	), buildEvidence(player))
	if Config.auditOnly then
		Logger.log("AUDIT (no action): " .. category .. " / " .. player.Name)
		return count
	end
	-- Escalation ladder: warn (log-only, already sent) -> kick
	-- at flagThreshold -> timed ban at banAt -> permanent ban
	-- at permAt. Cross-server totals can trip the kick even
	-- when this server's local count is still low.
	local kicked = false
	local crossTotal = crossServerBump(player.UserId)
	if crossTotal and crossTotal >= Config.flagThreshold and Config.kickOnDetect then
		Logger.kick(player, "Aegis: " .. category .. " (cross-server strikes)")
		kicked = true
	end
	if not kicked and Config.kickOnDetect and count >= Config.flagThreshold then
		Logger.kick(player, "Aegis: " .. category)
		kicked = true
	end
	if Config.bans.enabled then
		local esc = Config.escalation
		if esc.permAt and count >= esc.permAt then
			BanGuard.ban(player.UserId, 315360000, "Aegis: " .. category .. " (permanent)")
		elseif esc.banAt and count >= esc.banAt then
			BanGuard.ban(player.UserId, esc.banSeconds or 3600, "Aegis: " .. category)
		end
	end
	return count
end

function Logger.warn(player, category, detail)
	logEvent(string.format(
		"WARN %s (%d) [%s] %s",
		player.Name,
		player.UserId,
		category,
		detail or ""
	))
end

function Logger.kick(player, reason)
	logEvent("KICK " .. player.Name .. " (" .. player.UserId .. ") — " .. reason)
	pcall(function()
		player:Kick(reason)
	end)
end

function Logger.clear(player)
	local prefix = player.UserId .. ":"
	for k in pairs(strikes) do
		if k:sub(1, #prefix) == prefix then
			strikes[k] = nil
		end
	end
	recentCalls[player.UserId] = nil
end

--// TRUST

local trusted = {}

local function isTrusted(player)
	return trusted[player.UserId] == true
end

--// AIMBOT GUARD

local AimbotGuard = {}
local aimHistory = {}
local MAX_AIM_HISTORY = 30

local function angleBetween(a, b)
	return math.deg(math.acos(math.clamp(a:Dot(b), -1, 1)))
end

function AimbotGuard.trackShot(player, aimDir)
	if not Config.aimbot.enabled then
		return
	end
	if isTrusted(player) then
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

--// SESSION GUARD

local SessionGuard = {}
local activity = {}

function SessionGuard.ping(player)
	activity[player.UserId] = os.clock()
end

function SessionGuard.start()
	local cfg = Config.session
	if not cfg.enabled then
		return
	end
	for _, player in ipairs(Players:GetPlayers()) do
		activity[player.UserId] = os.clock()
	end
	Players.PlayerAdded:Connect(function(player)
		activity[player.UserId] = os.clock()
	end)
	Players.PlayerRemoving:Connect(function(player)
		activity[player.UserId] = nil
	end)
	task.spawn(function()
		while true do
			task.wait(cfg.checkInterval)
			local now = os.clock()
			for _, player in ipairs(Players:GetPlayers()) do
				if not isTrusted(player) then
					local lastActive = activity[player.UserId] or now
					if now - lastActive > cfg.maxIdle then
						Logger.kick(player, "Aegis: idle too long")
					end
				end
			end
		end
	end)
end

--// REMOTE VALIDATOR

local RemoteValidator = {}
local rateBuckets = {}

local function typeOk(value, expected)
	if expected == "any" then
		return true
	end
	if expected == "WorkspaceInstance" then
		-- An instance that really lives in the world: rejects
		-- client-forged parts and nil-parented smuggled objects.
		return typeof(value) == "Instance" and value:IsDescendantOf(Workspace)
	end
	return typeof(value) == expected
end

-- Player-arg binding: a remote argument naming a DIFFERENT
-- player than the caller is an impersonation attempt (grant
-- to a friend, punish a stranger) unless the caller is
-- trusted staff. Legit cross-player remotes (trades, targeting)
-- should disable this or route through trusted callers.
local function playerArgBound(player, args)
	if not Config.playerArgBinding then
		return true
	end
	for _, v in ipairs(args) do
		if typeof(v) == "Instance" and v:IsA("Player") and v ~= player then
			return false
		end
	end
	return true
end

-- Public helper version of the same rule, for game code that
-- validates instances outside a remote (tools, prompts).
local function validInstance(inst, className, mustBeInWorkspace)
	if typeof(inst) ~= "Instance" then
		return false
	end
	if className and not inst:IsA(className) then
		return false
	end
	if mustBeInWorkspace and not inst:IsDescendantOf(Workspace) then
		return false
	end
	return true
end

-- Finiteness is a separate check from type: a NaN still has
-- typeof "number", and a Vector3 can carry NaN components --
-- and NaN makes every magnitude/range comparison downstream
-- come back false, so range checks PASS on garbage. Reject
-- non-finite numbers anywhere in an argument, tables included
-- (depth-capped; sizeOk separately caps table breadth).
local function finiteOk(value, depth)
	local t = typeof(value)
	if t == "number" then
		return value == value and value ~= math.huge and value ~= -math.huge
	elseif t == "Vector3" then
		return value.X == value.X and value.Y == value.Y and value.Z == value.Z
			and math.abs(value.X) < 1e9 and math.abs(value.Y) < 1e9 and math.abs(value.Z) < 1e9
	elseif t == "CFrame" then
		local c = { value:GetComponents() }
		for i = 1, 12 do
			if c[i] ~= c[i] then
				return false
			end
		end
		return true
	elseif t == "table" then
		depth = depth or 0
		if depth >= 4 then
			return true
		end
		for k, v in pairs(value) do
			if not finiteOk(k, depth + 1) or not finiteOk(v, depth + 1) then
				return false
			end
		end
	end
	return true
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

Players.PlayerRemoving:Connect(function(player)
	local prefix = player.UserId .. "\0"
	for key in pairs(rateBuckets) do
		if key:sub(1, #prefix) == prefix then
			rateBuckets[key] = nil
		end
	end
	recentCalls[player.UserId] = nil
end)

local function globalRateOk(player)
	local limit = Config.globalRate
	if not limit or not limit[1] or limit[1] <= 0 then
		return true
	end
	return rateOk(player, "__global", limit)
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

function RemoteValidator.secure(remote, schemaOverride, handler)
	if typeof(schemaOverride) == "function" and handler == nil then
		handler = schemaOverride
		schemaOverride = nil
	end
	assert(typeof(handler) == "function", "Aegis.secure: handler must be a function")

	local schema = resolveSchema(remote, schemaOverride)

	remote.OnServerEvent:Connect(function(player, ...)
		if isTrusted(player) then
			local okT, errT = pcall(handler, player, ...)
			if not okT then
				Logger.log("handler error in " .. remote.Name .. ": " .. tostring(errT))
			end
			return
		end

		local args = { ... }
		recordCall(player, remote.Name, args)

		if not globalRateOk(player) then
			Logger.flag(player, "remote-spam", remote.Name .. " (global budget)")
			return
		end

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
			local optional = expected:sub(-1) == "?"
			if optional then
				expected = expected:sub(1, -2)
			end
			if v == nil then
				if optional or expected == "nil" then
					continue
				end
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
			if not finiteOk(v) then
				Logger.flag(player, "remote-args", remote.Name .. ": non-finite arg " .. i)
				return
			end
			if not sizeOk(v, schema.maxArgSize) then
				Logger.flag(player, "remote-crasher", remote.Name .. ": oversized arg " .. i)
				return
			end
		end

		if not playerArgBound(player, args) then
			Logger.flag(player, "remote-args", remote.Name .. ": arg names another player")
			return
		end

		if schema.trackAim then
			local dir = args[schema.aimArg]
			if typeof(dir) == "Vector3" then
				AimbotGuard.trackShot(player, dir)
			end
		end

		SessionGuard.ping(player)

		local ok, err = pcall(handler, player, ...)
		if not ok then
			Logger.log("handler error in " .. remote.Name .. ": " .. tostring(err))
		end
	end)
end

function RemoteValidator.secureFunction(rf, schemaOverride, handler)
	if typeof(schemaOverride) == "function" and handler == nil then
		handler = schemaOverride
		schemaOverride = nil
	end
	assert(typeof(handler) == "function", "Aegis.secureFunction: handler must be a function")

	local schema = resolveSchema(rf, schemaOverride)

	rf.OnServerInvoke = function(player, ...)
		if isTrusted(player) then
			return handler(player, ...)
		end

		local args = { ... }
		recordCall(player, rf.Name, args)

		if not globalRateOk(player) then
			Logger.flag(player, "remote-spam", rf.Name .. " (global budget)")
			return nil
		end

		if not rateOk(player, rf.Name, schema.rateLimit) then
			Logger.flag(player, "remote-spam", rf.Name)
			return nil
		end

		if #args > #schema.args then
			Logger.flag(player, "remote-args", rf.Name .. ": too many args")
			return nil
		end

		for i, expected in ipairs(schema.args) do
			local v = args[i]
			local optional = expected:sub(-1) == "?"
			if optional then
				expected = expected:sub(1, -2)
			end
			if v == nil then
				if optional or expected == "nil" then
					continue
				end
				Logger.flag(player, "remote-args", rf.Name .. ": missing arg " .. i)
				return nil
			end
			if not typeOk(v, expected) then
				Logger.flag(
					player,
					"remote-args",
					string.format(
						"%s: arg %d expected %s, got %s",
						rf.Name,
						i,
						expected,
						typeof(v)
					)
				)
				return nil
			end
			if not finiteOk(v) then
				Logger.flag(player, "remote-args", rf.Name .. ": non-finite arg " .. i)
				return nil
			end
			if not sizeOk(v, schema.maxArgSize) then
				Logger.flag(player, "remote-crasher", rf.Name .. ": oversized arg " .. i)
				return nil
			end
		end

		if not playerArgBound(player, args) then
			Logger.flag(player, "remote-args", rf.Name .. ": arg names another player")
			return nil
		end

		SessionGuard.ping(player)

		local results = { pcall(handler, player, ...) }
		if not results[1] then
			Logger.log("handler error in " .. rf.Name .. ": " .. tostring(results[2]))
			return nil
		end
		return table.unpack(results, 2)
	end
end

--// MOVEMENT GUARD

local MovementGuard = {}
local moveLast = {}
local moveExempt = {}
local flyAir = {}

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
	local function watchPlayer(player)
		player.CharacterAdded:Connect(function()
			moveLast[player.UserId] = nil
			moveExempt[player.UserId] = nil
			flyAir[player.UserId] = 0
		end)
	end
	Players.PlayerAdded:Connect(watchPlayer)
	for _, player in ipairs(Players:GetPlayers()) do
		watchPlayer(player)
	end
	Players.PlayerRemoving:Connect(function(player)
		moveLast[player.UserId] = nil
		moveExempt[player.UserId] = nil
		flyAir[player.UserId] = nil
	end)
end

function MovementGuard.checkAll(cfg)
	local dt = cfg.checkInterval
	for _, player in ipairs(Players:GetPlayers()) do
		local character = player.Character
		local hrp = character and character:FindFirstChild("HumanoidRootPart")
		local humanoid = character and character:FindFirstChildOfClass("Humanoid")
		if not isTrusted(player) and hrp and humanoid and humanoid.Health > 0 then
			local uid = player.UserId
			local pos = hrp.Position

			if moveExempt[uid] then
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
					moveLast[uid] = pos
				else
					local prev = moveLast[uid]
					moveLast[uid] = pos
					if prev then
						local delta = pos - prev
						local hDist = Vector3.new(delta.X, 0, delta.Z).Magnitude
						local vDist = math.abs(delta.Y)
						local speed = humanoid.WalkSpeed
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
							-- Rollback: snap back to the last
							-- legal position instead of letting
							-- the cheated position become the
							-- new baseline. Audit mode never
							-- corrects -- it only flags.
							if cfg.rollback and not Config.auditOnly and prev then
								hrp.CFrame = CFrame.new(prev)
								hrp.AssemblyLinearVelocity = Vector3.zero
								moveLast[uid] = prev
							end
						end

						-- Fly: airborne with ~zero vertical
						-- velocity (not falling, not jumping,
						-- not swimming) for flySeconds straight.
						-- Jump apexes are fractions of a second,
						-- so the threshold keeps them clean.
						if state ~= Enum.HumanoidStateType.Swimming then
							local flyParams = RaycastParams.new()
							flyParams.FilterType = Enum.RaycastFilterType.Exclude
							flyParams.FilterDescendantsInstances = { character }
							local ground = Workspace:Raycast(pos, Vector3.new(0, -6, 0), flyParams)
							if not ground and math.abs(hrp.AssemblyLinearVelocity.Y) < 2 then
								flyAir[uid] = (flyAir[uid] or 0) + dt
								if flyAir[uid] > cfg.flySeconds then
									Logger.flag(player, "fly", string.format("hovering %.1fs", flyAir[uid]))
									flyAir[uid] = 0
								end
							else
								flyAir[uid] = 0
							end
						end

						-- Fling: horizontal physics velocity no
						-- legitimate movement reaches. Falls are
						-- vertical, so they never trip this; a
						-- fling victim flies sideways.
						if cfg.flingSpeed > 0 then
							local hVel = Vector3.new(
								hrp.AssemblyLinearVelocity.X,
								0,
								hrp.AssemblyLinearVelocity.Z
							).Magnitude
							if hVel > cfg.flingSpeed then
								local nearest, nearestD = nil, 30
								for _, other in ipairs(Players:GetPlayers()) do
									if other ~= player and other.Character then
										local oroot = other.Character:FindFirstChild("HumanoidRootPart")
										if oroot then
											local d = (oroot.Position - pos).Magnitude
											if d < nearestD then
												nearest, nearestD = other, d
											end
										end
									end
								end
								Logger.flag(player, "fling", string.format(
									"h-vel %.0f (nearest %s)",
									hVel,
									nearest and nearest.Name or "none"
								))
							end
						end
					end
				end
			end
		end
	end
end

--// NOCLIP GUARD

local NoclipGuard = {}
local noclipLast = {}
local noclipSkip = {}

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
	local function watchPlayer(player)
		player.CharacterAdded:Connect(function()
			noclipLast[player.UserId] = nil
			noclipSkip[player.UserId] = nil
		end)
	end
	Players.PlayerAdded:Connect(watchPlayer)
	for _, player in ipairs(Players:GetPlayers()) do
		watchPlayer(player)
	end
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
		if not isTrusted(player) and hrp and humanoid and humanoid.Health > 0 then
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

					local dir = pos - prev
					local hit = Workspace:Raycast(prev, dir, params)
					if hit and hit.Instance.CanCollide and hit.Normal.Y < 0.7 then
						Logger.flag(player, "noclip", "crossed " .. hit.Instance:GetFullName())
					else
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

--// COMBAT GUARD

local CombatGuard = {}
local loadouts = {}

function CombatGuard.start()
	Players.PlayerRemoving:Connect(function(player)
		loadouts[player.UserId] = nil
	end)
end

function CombatGuard.register(player, spec)
	assert(
		spec.magSize and spec.fireInterval and spec.reloadTime,
		"registerWeapon: spec needs magSize, fireInterval, reloadTime"
	)
	loadouts[player.UserId] = {
		ammo = spec.magSize,
		magSize = spec.magSize,
		fireInterval = spec.fireInterval,
		reloadTime = spec.reloadTime,
		lastShot = 0,
		reloadEnd = 0,
		reloading = false,
		intervals = {},
	}
end

function CombatGuard.tryFire(player)
	if not Config.combat.enabled then
		return true
	end
	if isTrusted(player) then
		return true
	end
	local w = loadouts[player.UserId]
	if not w then
		return true
	end
	local now = os.clock()
	if w.reloading then
		if now >= w.reloadEnd then
			w.ammo = w.magSize
			w.reloading = false
		else
			return false
		end
	end
	if w.ammo <= 0 then
		Logger.flag(player, "combat", "fired with empty mag")
		return false
	end
	local interval = now - w.lastShot
	if w.lastShot > 0 and interval < w.fireInterval * 0.9 then
		Logger.flag(
			player,
			"combat",
			string.format("fire-rate %.3fs < %.3fs", interval, w.fireInterval)
		)
		return false
	end
	w.ammo -= 1
	if w.lastShot > 0 then
		table.insert(w.intervals, interval)
		if #w.intervals > Config.combat.consistencyWindow then
			table.remove(w.intervals, 1)
		end
		if #w.intervals >= Config.combat.consistencyWindow then
			local avg = 0
			for _, v in ipairs(w.intervals) do
				avg += v
			end
			avg /= #w.intervals
			local consistent = avg > 0.01
			if consistent then
				for _, v in ipairs(w.intervals) do
					if math.abs(v - avg) / avg > Config.combat.consistencyTolerance then
						consistent = false
						break
					end
				end
			end
			if consistent then
				Logger.warn(player, "combat", "inhuman fire consistency")
				w.intervals = {}
			end
		end
	end
	w.lastShot = now
	return true
end

function CombatGuard.reload(player)
	if not Config.combat.enabled then
		return
	end
	if isTrusted(player) then
		return
	end
	local w = loadouts[player.UserId]
	if not w then
		return
	end
	if w.reloading then
		Logger.flag(player, "combat", "reload timer skipped")
		return
	end
	w.reloading = true
	w.reloadEnd = os.clock() + w.reloadTime
end

--// HIT VALIDATOR

local HitValidator = {}

function HitValidator.validate(player, targetPosition, maxRange)
	if isTrusted(player) then
		return true
	end
	if typeof(targetPosition) ~= "Vector3" or typeof(maxRange) ~= "number" then
		return false
	end
	local character = player.Character
	local hrp = character and character:FindFirstChild("HumanoidRootPart")
	if not hrp then
		return false
	end
	local dist = (hrp.Position - targetPosition).Magnitude
	if dist > maxRange then
		Logger.flag(
			player,
			"kill-aura",
			string.format("hit at %.1f (max %.1f)", dist, maxRange)
		)
		return false
	end
	return true
end

--// INVENTORY GUARD

local InventoryGuard = {}
local inventories = {}
local invLocks = {}
local invStore = nil

function InventoryGuard.setDataStore(ds)
	invStore = ds
end

local function invPersist(player)
	if not invStore then
		return
	end
	local uid = player.UserId
	local data = inventories[uid] or {}
	local ok, err = pcall(function()
		invStore:UpdateAsync("aegis_inv_" .. uid, function()
			return data
		end)
	end)
	if not ok then
		Logger.log("inventory persist failed: " .. tostring(err))
	end
end

local function acquire(uids)
	local waited = 0
	while waited < 5 do
		local free = true
		for _, uid in ipairs(uids) do
			if invLocks[uid] then
				free = false
				break
			end
		end
		if free then
			for _, uid in ipairs(uids) do
				invLocks[uid] = true
			end
			return true
		end
		task.wait(0.05)
		waited += 0.05
	end
	return false
end

local function release(uids)
	for _, uid in ipairs(uids) do
		invLocks[uid] = nil
	end
end

local function withLock(uids, fn)
	if not acquire(uids) then
		return false
	end
	local ok, result = pcall(fn)
	release(uids)
	if not ok then
		Logger.log("inventory transaction error: " .. tostring(result))
		return false
	end
	return result
end

-- Amounts and stored values are sanitized at every boundary:
-- a NaN or infinite count poisons every comparison it touches
-- and cannot be JSON-encoded for the DataStore, so it must
-- never enter (or survive in) an inventory. Bad amounts floor
-- to a minimum of 1 for forgiving callers, but a poisoned
-- STORED value reads as 0 and is overwritten on next mutation.
local MAX_STACK = 1e12

local function cleanAmount(amount)
	if typeof(amount) ~= "number" or amount ~= amount
		or amount == math.huge or amount == -math.huge
	then
		return 1
	end
	return math.clamp(math.floor(amount), 1, MAX_STACK)
end

local function cleanStored(value)
	if typeof(value) ~= "number" or value ~= value
		or value == math.huge or value == -math.huge or value < 0
	then
		return 0
	end
	return math.min(math.floor(value), MAX_STACK)
end

local function validItemId(itemId)
	return typeof(itemId) == "string" or typeof(itemId) == "number"
end

local function getInv(player)
	local inv = inventories[player.UserId]
	if not inv then
		inv = {}
		inventories[player.UserId] = inv
	end
	return inv
end

-- Honeypot items: item ids no legitimate path can ever
-- grant (register with addHoneypotItem). Possession is a
-- certain exploit by construction -- same zero-false-positive
-- idea as the decoy remotes, applied to inventory.
function InventoryGuard.addHoneypotItem(itemId)
	Config.honeypot.items[itemId] = true
end

local function isHoneypotItem(itemId)
	return Config.honeypot.items[itemId] == true
end

function InventoryGuard.load(player, data)
	local clean = {}
	if typeof(data) == "table" then
		for itemId, value in pairs(data) do
			if validItemId(itemId) then
				if isHoneypotItem(itemId) then
					-- Saved data carrying a trap item: strip
					-- it and flag. No legit save contains it.
					Logger.flag(player, "honeypot-item", "loaded " .. tostring(itemId))
				else
					local n = cleanStored(value)
					if n > 0 then
						clean[itemId] = n
					end
				end
			end
		end
	end
	inventories[player.UserId] = clean
end

function InventoryGuard.start()
	Players.PlayerRemoving:Connect(function(player)
		inventories[player.UserId] = nil
		invLocks[player.UserId] = nil
	end)
end

function InventoryGuard.get(player)
	local copy = {}
	for k, v in pairs(getInv(player)) do
		copy[k] = v
	end
	return copy
end

function InventoryGuard.has(player, itemId, amount)
	if not validItemId(itemId) then
		return false
	end
	amount = cleanAmount(amount or 1)
	return cleanStored(getInv(player)[itemId]) >= amount
end

function InventoryGuard.give(player, itemId, amount)
	if not validItemId(itemId) then
		return false
	end
	if isHoneypotItem(itemId) then
		Logger.flag(player, "honeypot-item", "granted " .. tostring(itemId))
		return false
	end
	amount = cleanAmount(amount or 1)
	return withLock({ player.UserId }, function()
		local inv = getInv(player)
		inv[itemId] = math.min(cleanStored(inv[itemId]) + amount, MAX_STACK)
		invPersist(player)
		return true
	end)
end

function InventoryGuard.take(player, itemId, amount)
	if not validItemId(itemId) then
		return false
	end
	amount = cleanAmount(amount or 1)
	return withLock({ player.UserId }, function()
		local inv = getInv(player)
		if cleanStored(inv[itemId]) < amount then
			return false
		end
		inv[itemId] = cleanStored(inv[itemId]) - amount
		if inv[itemId] <= 0 then
			inv[itemId] = nil
		end
		invPersist(player)
		return true
	end)
end

function InventoryGuard.trade(fromPlayer, toPlayer, itemId, amount)
	if not validItemId(itemId) then
		return false
	end
	amount = cleanAmount(amount or 1)
	local first, second = fromPlayer, toPlayer
	if fromPlayer.UserId > toPlayer.UserId then
		first, second = toPlayer, fromPlayer
	end
	return withLock({ first.UserId, second.UserId }, function()
		local fromInv = getInv(fromPlayer)
		if cleanStored(fromInv[itemId]) < amount then
			Logger.flag(fromPlayer, "dupe", "trade without owning " .. tostring(itemId))
			return false
		end
		fromInv[itemId] = cleanStored(fromInv[itemId]) - amount
		if fromInv[itemId] <= 0 then
			fromInv[itemId] = nil
		end
		local toInv = getInv(toPlayer)
		toInv[itemId] = math.min(cleanStored(toInv[itemId]) + amount, MAX_STACK)
		invPersist(fromPlayer)
		invPersist(toPlayer)
		return true
	end)
end

--// SHOP GUARD

local ShopGuard = {}
local catalog = {}
local receipts = {}

function ShopGuard.start()
	Players.PlayerRemoving:Connect(function(player)
		receipts[player.UserId] = nil
	end)
end

function ShopGuard.setCatalog(c)
	local old = catalog
	catalog = c or {}
	return old
end

-- Idempotent buys: pass a receipt id (a GUID per purchase
-- click) and a lag-replayed buy grants exactly once. The
-- receipt is checked BEFORE any coins move, so a replay
-- costs nothing and grants nothing. Calls without a receipt
-- behave exactly as before.
function ShopGuard.buy(player, itemId, receiptId)
	local entry = catalog[itemId]
	if not entry then
		Logger.flag(player, "shop", "buy unknown item: " .. tostring(itemId))
		return false
	end
	local seen = nil
	if receiptId ~= nil then
		seen = receipts[player.UserId]
		if not seen then
			seen = {}
			receipts[player.UserId] = seen
		end
		if seen[receiptId] then
			return false
		end
	end
	if not InventoryGuard.take(player, entry.currency or "coins", entry.price) then
		return false
	end
	InventoryGuard.give(player, itemId, 1)
	if seen then
		seen[receiptId] = os.clock()
		local n = 0
		for _ in pairs(seen) do
			n += 1
		end
		if n > 64 then
			receipts[player.UserId] = { [receiptId] = os.clock() }
		end
	end
	return true
end

--// BEHAVIOR GUARD

local BehaviorGuard = {}
local actionStreams = {}
local actionSessions = {}
local adaptiveStreams = {}

function BehaviorGuard.start()
	Players.PlayerRemoving:Connect(function(player)
		actionSessions[player.UserId] = nil
		local prefix = player.UserId .. "\0"
		for k in pairs(actionStreams) do
			if k:sub(1, #prefix) == prefix then
				actionStreams[k] = nil
			end
		end
		for k in pairs(adaptiveStreams) do
			if k:sub(1, #prefix) == prefix then
				adaptiveStreams[k] = nil
			end
		end
	end)
end

function BehaviorGuard.record(player, action)
	if not Config.behavior.enabled then
		return
	end
	if isTrusted(player) then
		return
	end
	local cfg = Config.behavior
	local now = os.clock()
	local uid = player.UserId

	local sess = actionSessions[uid]
	if not sess or now - sess.last > cfg.breakReset then
		sess = { start = now, last = now, actions = 0 }
		actionSessions[uid] = sess
	end
	sess.last = now
	sess.actions += 1
	if sess.actions >= cfg.marathonActions and now - sess.start >= cfg.marathonSeconds then
		Logger.warn(player, "autofarm", "marathon: " .. sess.actions .. " actions")
		actionSessions[uid] = nil
	end

	local key = uid .. "\0" .. action
	local s = actionStreams[key]
	if not s then
		s = {}
		actionStreams[key] = s
	end
	table.insert(s, now)
	if #s > 120 then
		table.remove(s, 1)
	end
	if #s >= cfg.consistencyWindow + 1 then
		local intervals = {}
		for i = #s - cfg.consistencyWindow + 1, #s do
			table.insert(intervals, s[i] - s[i - 1])
		end
		local avg = 0
		for _, v in ipairs(intervals) do
			avg += v
		end
		avg /= #intervals
		if avg > 0.05 then
			local consistent = true
			for _, v in ipairs(intervals) do
				if math.abs(v - avg) / avg > cfg.consistencyTolerance then
					consistent = false
					break
				end
			end
			if consistent then
				Logger.warn(player, "autofarm", action .. ": metronome timing")
				actionStreams[key] = {}
			end
		end
	end

	-- Adaptive baseline: the same action over a longer window,
	-- scored by coefficient of variation (stddev / mean). A bot
	-- holds machine-consistent intervals at ANY speed; humans
	-- wobble. Only fast actions qualify, so slow deliberate
	-- play never trips it. Warn-only, like the metronome check.
	local ast = adaptiveStreams[key]
	if not ast then
		ast = { last = 0, intervals = {} }
		adaptiveStreams[key] = ast
	end
	if ast.last > 0 then
		table.insert(ast.intervals, now - ast.last)
		if #ast.intervals > cfg.adaptiveWindow then
			table.remove(ast.intervals, 1)
		end
		if #ast.intervals >= 20 then
			local mean = 0
			for _, v in ipairs(ast.intervals) do
				mean += v
			end
			mean /= #ast.intervals
			local variance = 0
			for _, v in ipairs(ast.intervals) do
				variance += (v - mean) * (v - mean)
			end
			variance /= #ast.intervals
			local cv = mean > 0 and math.sqrt(variance) / mean or 0
			if mean < cfg.adaptiveMaxMean and cv < cfg.adaptiveMaxCV then
				Logger.warn(player, "autofarm", string.format(
					"%s: bot-like timing (CV %.3f)", action, cv
				))
				ast.intervals = {}
			end
		end
	end
	ast.last = now
end

--// CLIENT COMPANION
-- Optional LocalScript tripwire (see AegisClient.lua): it pings
-- this remote every 20s. Presence is supporting evidence only
-- -- an exploiter can delete any LocalScript, so a missing ping
-- NEVER flags anyone by itself. The server stays the truth.
local ClientCompanion = {}
local lastPing = {}

function ClientCompanion.start()
	local folder = ReplicatedStorage:FindFirstChild("Remotes")
	if not folder then
		folder = Instance.new("Folder")
		folder.Name = "Remotes"
		folder.Parent = ReplicatedStorage
	end
	if folder:FindFirstChild("AegisClientPing") then
		return
	end
	local ping = Instance.new("RemoteEvent")
	ping.Name = "AegisClientPing"
	ping.Parent = folder
	ping.OnServerEvent:Connect(function(player)
		SessionGuard.ping(player)
		lastPing[player.UserId] = os.clock()
	end)
	Players.PlayerRemoving:Connect(function(player)
		lastPing[player.UserId] = nil
	end)
end

function ClientCompanion.status(player)
	local t = lastPing[player.UserId]
	if not t then
		return nil
	end
	return os.clock() - t
end

--// PUBLIC API

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

--// HONEYPOT GUARD
-- Decoy remotes no legitimate client ever fires (they are not
-- in the game's real remote list -- an exploiter enumerating
-- ReplicatedStorage finds them and cannot resist). Any call is
-- a certain flag: zero false positives by construction.

local HoneypotGuard = {}

function HoneypotGuard.start()
	if not Config.honeypot.enabled then
		return
	end
	local folder = ReplicatedStorage:FindFirstChild("Remotes")
	if not folder then
		folder = Instance.new("Folder")
		folder.Name = "Remotes"
		folder.Parent = ReplicatedStorage
	end
	for _, name in ipairs(Config.honeypot.names) do
		if not folder:FindFirstChild(name) then
			local decoy = Instance.new("RemoteEvent")
			decoy.Name = name
			decoy.Parent = folder
			decoy.OnServerEvent:Connect(function(player)
				Logger.flag(player, "honeypot", name)
			end)
		end
	end
end

--// BAN GUARD
-- Timed bans with expiry, persisted in a DataStore. Checked on
-- join; banned players are kicked with the reason. Opt-in:
-- Config.bans.enabled (off by default -- a kit should not start
-- banning people because someone pasted it in).

BanGuard = {}
local banStore = nil

local function banStoreReady()
	if banStore then
		return true
	end
	local ok, store = pcall(function()
		return DataStoreService:GetDataStore(Config.bans.storeName)
	end)
	if ok then
		banStore = store
	end
	return banStore ~= nil
end

function BanGuard.ban(userId, durationSeconds, reason)
	if not banStoreReady() then
		return false
	end
	local record = {
		untilAt = os.time() + math.max(60, math.floor(durationSeconds or 3600)),
		reason = tostring(reason or "banned"),
	}
	local ok = pcall(function()
		banStore:SetAsync("ban_" .. userId, record)
	end)
	if ok then
		local player = Players:GetPlayerByUserId(userId)
		if player then
			pcall(Logger.kick, player, "Banned: " .. record.reason)
		end
	end
	return ok
end

function BanGuard.unban(userId)
	if not banStoreReady() then
		return false
	end
	return pcall(function()
		banStore:RemoveAsync("ban_" .. userId)
	end)
end

function BanGuard.check(player)
	if not banStoreReady() then
		return
	end
	local ok, record = pcall(function()
		return banStore:GetAsync("ban_" .. player.UserId)
	end)
	if ok and typeof(record) == "table" and typeof(record.untilAt) == "number" then
		if record.untilAt > os.time() then
			Logger.kick(player, "Banned: " .. tostring(record.reason or ""))
		else
			BanGuard.unban(player.UserId)
		end
	end
end

local banStarted = false

function BanGuard.start()
	if banStarted then
		return
	end
	if not Config.bans.enabled then
		return
	end
	banStarted = true
	Players.PlayerAdded:Connect(BanGuard.check)
	for _, player in ipairs(Players:GetPlayers()) do
		task.spawn(BanGuard.check, player)
	end
end

-- Deep-clean a value for DataStore saving: NaN/inf numbers
-- become 0 (JSON cannot encode them and one poisoned leaf
-- fails the whole save), non-serializable values are dropped,
-- tables are copied (depth-capped). Use before SetAsync.
local function sanitizeData(value, depth)
	depth = depth or 0
	local t = typeof(value)
	if t == "number" then
		if value ~= value or value == math.huge or value == -math.huge then
			return 0
		end
		return value
	elseif t == "string" or t == "boolean" then
		return value
	elseif t == "table" then
		if depth >= 8 then
			return nil
		end
		local out = {}
		for k, v in pairs(value) do
			local keyOk = typeof(k) == "string" or typeof(k) == "number"
			local cleaned = sanitizeData(v, depth + 1)
			if keyOk and cleaned ~= nil then
				out[k] = cleaned
			end
		end
		return out
	end
	return nil
end

-- One-line profiles. Apply BEFORE init (or call init again
-- after -- guards read Config at start). Strict opts into bans,
-- which is the point of strict; audit never bans anyone.
local presets = {
	audit = { auditOnly = true, kickOnDetect = false },
	casual = { auditOnly = false, kickOnDetect = true, flagThreshold = 3 },
	strict = {
		auditOnly = false,
		kickOnDetect = true,
		flagThreshold = 2,
		bans = { enabled = true },
		escalation = { banAt = 4, banSeconds = 3600, permAt = 8 },
	},
}

function Aegis.preset(name)
	local p = presets[name]
	assert(p, "Aegis.preset: unknown preset '" .. tostring(name) .. "' (audit/casual/strict)")
	Aegis.configure(p)
	if p.bans and p.bans.enabled then
		BanGuard.start()
	end
	return Aegis
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
	SessionGuard.start()
	CombatGuard.start()
	InventoryGuard.start()
	BehaviorGuard.start()
	HoneypotGuard.start()
	BanGuard.start()
	ShopGuard.start()
	if Config.webhookDigest then
		task.spawn(function()
			while true do
				task.wait(3600)
				Logger.flushDigest()
			end
		end)
	end
	Logger.log("Aegis v0.5 initialized")
	return Aegis
end

local function ensureStarted()
	if not started then
		Aegis.init()
	end
end

function Aegis.secure(remote, schema, handler)
	ensureStarted()
	return RemoteValidator.secure(remote, schema, handler)
end

function Aegis.secureFunction(rf, schema, handler)
	ensureStarted()
	return RemoteValidator.secureFunction(rf, schema, handler)
end

function Aegis.teleport(player, cframe)
	ensureStarted()
	MovementGuard.exempt(player, cframe)
	NoclipGuard.exempt(player)
	local hrp = player.Character and player.Character:FindFirstChild("HumanoidRootPart")
	if hrp then
		hrp.CFrame = cframe
	end
end

function Aegis.reportShot(player, aimDirection)
	ensureStarted()
	AimbotGuard.trackShot(player, aimDirection)
end

function Aegis.trust(player)
	trusted[player.UserId] = true
end

function Aegis.untrust(player)
	trusted[player.UserId] = nil
end

function Aegis.registerWeapon(player, spec)
	ensureStarted()
	CombatGuard.register(player, spec)
end

function Aegis.tryFire(player)
	ensureStarted()
	return CombatGuard.tryFire(player)
end

function Aegis.reloadWeapon(player)
	ensureStarted()
	CombatGuard.reload(player)
end

function Aegis.validateHit(player, targetPosition, maxRange)
	ensureStarted()
	return HitValidator.validate(player, targetPosition, maxRange)
end

function Aegis.ping(player)
	ensureStarted()
	SessionGuard.ping(player)
end

function Aegis.ban(userId, durationSeconds, reason)
	ensureStarted()
	return BanGuard.ban(userId, durationSeconds, reason)
end

function Aegis.unban(userId)
	ensureStarted()
	return BanGuard.unban(userId)
end

function Aegis.sanitizeData(value)
	return sanitizeData(value)
end

function Aegis.setDataStore(ds)
	InventoryGuard.setDataStore(ds)
end

function Aegis.loadInventory(player, data)
	ensureStarted()
	InventoryGuard.load(player, data)
end

function Aegis.getInventory(player)
	ensureStarted()
	return InventoryGuard.get(player)
end

function Aegis.hasItem(player, itemId, amount)
	ensureStarted()
	return InventoryGuard.has(player, itemId, amount)
end

function Aegis.giveItem(player, itemId, amount)
	ensureStarted()
	return InventoryGuard.give(player, itemId, amount)
end

function Aegis.takeItem(player, itemId, amount)
	ensureStarted()
	return InventoryGuard.take(player, itemId, amount)
end

function Aegis.tradeItems(fromPlayer, toPlayer, itemId, amount)
	ensureStarted()
	return InventoryGuard.trade(fromPlayer, toPlayer, itemId, amount)
end

function Aegis.setShop(catalog)
	ShopGuard.setCatalog(catalog)
end

function Aegis.buyItem(player, itemId, receiptId)
	ensureStarted()
	return ShopGuard.buy(player, itemId, receiptId)
end

function Aegis.recordAction(player, action)
	ensureStarted()
	BehaviorGuard.record(player, action)
end

function Aegis.validInstance(inst, className, mustBeInWorkspace)
	return validInstance(inst, className, mustBeInWorkspace)
end

function Aegis.addHoneypotItem(itemId)
	ensureStarted()
	return InventoryGuard.addHoneypotItem(itemId)
end

function Aegis.initClientCompanion()
	ensureStarted()
	return ClientCompanion.start()
end

-- Seconds since this player's client last pinged, or nil when
-- the companion never reported (companion not installed, or
-- deleted -- which by itself proves nothing).
function Aegis.getClientStatus(player)
	return ClientCompanion.status(player)
end

function Aegis.flushDigest()
	return Logger.flushDigest()
end

-- Dev-only guard verification. Run from the Studio command bar
-- after require()ing Aegis with selfTestEnabled = true. Runs
-- under forced audit rules, so no test flag can kick anyone,
-- and restores your settings afterwards. Movement / fly /
-- fling / noclip are tick-based and cannot be scripted here --
-- move the test character to verify those by hand.
function Aegis.selfTest()
	if not Config.selfTestEnabled then
		Logger.log("selfTest disabled: Aegis.configure({ selfTestEnabled = true }) first")
		return nil
	end
	local savedAudit, savedKick = Config.auditOnly, Config.kickOnDetect
	Config.auditOnly, Config.kickOnDetect = true, false
	local results = {}
	local function check(name, fn)
		local ok, res = pcall(fn)
		if ok and res == "SKIP" then
			results[name] = "SKIP"
			print("[Aegis self-test] " .. name .. ": SKIP")
			return
		end
		local pass = ok and res ~= false
		results[name] = pass
		print("[Aegis self-test] " .. name .. ": " .. (pass and "PASS" or "FAIL"))
	end
	local fake = { UserId = 987654321, Name = "SelfTest" }
	check("finite rejects NaN", function()
		return finiteOk(0 / 0) == false
	end)
	check("finite rejects inf Vector3", function()
		return finiteOk(Vector3.new(0, math.huge, 0)) == false
	end)
	check("size rejects oversized string", function()
		return sizeOk(string.rep("x", 3000), 2048) == false
	end)
	check("rate limiter trips", function()
		for _ = 1, 25 do
			rateOk(fake, "SelfTestRemote", { 20, 1 })
		end
		local tripped = rateOk(fake, "SelfTestRemote", { 20, 1 }) == false
		rateBuckets[fake.UserId .. "\0SelfTestRemote"] = nil
		return tripped
	end)
	check("honeypot item grant refused", function()
		InventoryGuard.addHoneypotItem("SELFTEST_GOD")
		return InventoryGuard.give(fake, "SELFTEST_GOD", 1) == false
	end)
	check("honeypot item stripped on load", function()
		InventoryGuard.load(fake, { SELFTEST_GOD = 5, coins = 10 })
		return InventoryGuard.has(fake, "SELFTEST_GOD", 1) == false
			and InventoryGuard.has(fake, "coins", 10) == true
	end)
	check("shop receipt replay grants once", function()
		local oldCatalog = ShopGuard.setCatalog({ sword = { price = 10, currency = "coins" } })
		InventoryGuard.load(fake, { coins = 100 })
		local first = ShopGuard.buy(fake, "sword", "receipt-1")
		local second = ShopGuard.buy(fake, "sword", "receipt-1")
		ShopGuard.setCatalog(oldCatalog)
		return first == true and second == false
	end)
	local players = Players:GetPlayers()
	if #players >= 2 then
		check("player-arg binding", function()
			return playerArgBound(players[1], { players[2] }) == false
				and playerArgBound(players[1], { players[1] }) == true
		end)
	else
		results["player-arg binding"] = "SKIP"
		print("[Aegis self-test] player-arg binding: SKIP (needs 2 players in-game)")
	end
	check("cross-server map reachable", function()
		local ok = pcall(function()
			return MemoryStoreService:GetSortedMap(Config.crossServer.mapName)
		end)
		if not ok then
			return "SKIP"
		end
		return true
	end)
	check("escalation config sane", function()
		local esc = Config.escalation
		if esc.banAt and esc.banAt <= Config.flagThreshold then
			return false
		end
		if esc.permAt and esc.banAt and esc.permAt <= esc.banAt then
			return false
		end
		return true
	end)
	Config.honeypot.items["SELFTEST_GOD"] = nil
	Logger.clear(fake)
	Config.auditOnly, Config.kickOnDetect = savedAudit, savedKick
	local passed, total = 0, 0
	for _, v in pairs(results) do
		if v ~= "SKIP" then
			total += 1
			if v then
				passed += 1
			end
		end
	end
	print(string.format("[Aegis self-test] %d/%d passed", passed, total))
	print("[Aegis self-test] NOTE: movement/fly/fling/noclip are tick-based -- move the test character to verify them")
	return results
end

Aegis.Config = Config
Aegis.Logger = Logger

return Aegis
