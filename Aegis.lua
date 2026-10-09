--// Aegis v0.2 — open-source anti-exploit kit for Roblox games.
--// One ModuleScript in ServerScriptService. MIT License.
--// Built by Dakait — https://dakait.lol
--//
--// INDEX (top to bottom):
--//   Config ........... kick policy, audit mode, remote defaults,
--//                      per-remote overrides, guard tuning
--//   Logger ........... flag() strikes, warn() log-only, kick(), discord webhook
--//   Trust ............ Aegis.trust(): exempt staff/testers from all guards
--//   AimbotGuard ...... trackShot(): snap angles + tracking consistency, flag-only
--//   SessionGuard ..... server-side AFK tracking (server kicks can't be hooked)
--//   RemoteValidator .. secure(): arg types, rate limits, arg size caps
--//   MovementGuard .... displacement checks: speed, teleport, tween, pivot
--//   NoclipGuard ...... path raycasts + inside-geometry checks
--//   CombatGuard ...... registerWeapon/tryFire/reloadWeapon: server-side ammo,
--//                      fire-rate, reload timers, trigger-bot check (warn-only)
--//   HitValidator ..... validateHit(): kill-aura range checks
--//   InventoryGuard ... give/take/trade: atomic, locked, persisted on every
--//                      mutation (kills script dupes + wifi-freeze dupes)
--//   ShopGuard ........ server-side catalog prices, balance-checked buys
--//   BehaviorGuard .... recordAction(): farm-bot timing + marathon heuristics
--//   Public API ....... init / configure / secure / teleport / reportShot /
--//                      trust / untrust / registerWeapon / tryFire /
--//                      reloadWeapon / validateHit / ping / giveItem / takeItem /
--//                      tradeItems / hasItem / setShop / buyItem / recordAction
--//
--// Install: paste this whole file into a ModuleScript named "Aegis".
--// Usage:
--//   local Aegis = require(game.ServerScriptService.Aegis)
--//   Aegis.init()
--//   Aegis.secure(remote, { args = {"number"} }, function(player, ...) end)

local Players = game:GetService("Players")
local Workspace = game:GetService("Workspace")
local HttpService = game:GetService("HttpService")

local Aegis = {}

--// CONFIG

local Config = {
	kickOnDetect = true,
	flagThreshold = 3,
	discordWebhook = "",
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
	},
}

--// LOGGER

local Logger = {}
local strikes = {}

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
	if Config.auditOnly then
		Logger.log("AUDIT (no action): " .. category .. " / " .. player.Name)
		return count
	end
	if Config.kickOnDetect and count >= Config.flagThreshold then
		Logger.kick(player, "Aegis: " .. category)
	end
	return count
end

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

		SessionGuard.ping(player)

		local ok, err = pcall(handler, player, ...)
		if not ok then
			Logger.log("handler error in " .. remote.Name .. ": " .. tostring(err))
		end
	end)
end

--// MOVEMENT GUARD

local MovementGuard = {}
local moveLast = {}
local moveExempt = {}

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
		end)
	end
	Players.PlayerAdded:Connect(watchPlayer)
	for _, player in ipairs(Players:GetPlayers()) do
		watchPlayer(player)
	end
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

local function getInv(player)
	local inv = inventories[player.UserId]
	if not inv then
		inv = {}
		inventories[player.UserId] = inv
	end
	return inv
end

function InventoryGuard.load(player, data)
	inventories[player.UserId] = data or {}
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
	amount = math.max(1, math.floor(amount or 1))
	return (getInv(player)[itemId] or 0) >= amount
end

function InventoryGuard.give(player, itemId, amount)
	amount = math.max(1, math.floor(amount or 1))
	return withLock({ player.UserId }, function()
		local inv = getInv(player)
		inv[itemId] = (inv[itemId] or 0) + amount
		invPersist(player)
		return true
	end)
end

function InventoryGuard.take(player, itemId, amount)
	amount = math.max(1, math.floor(amount or 1))
	return withLock({ player.UserId }, function()
		local inv = getInv(player)
		if (inv[itemId] or 0) < amount then
			return false
		end
		inv[itemId] -= amount
		if inv[itemId] <= 0 then
			inv[itemId] = nil
		end
		invPersist(player)
		return true
	end)
end

function InventoryGuard.trade(fromPlayer, toPlayer, itemId, amount)
	amount = math.max(1, math.floor(amount or 1))
	local first, second = fromPlayer, toPlayer
	if fromPlayer.UserId > toPlayer.UserId then
		first, second = toPlayer, fromPlayer
	end
	return withLock({ first.UserId, second.UserId }, function()
		local fromInv = getInv(fromPlayer)
		if (fromInv[itemId] or 0) < amount then
			Logger.flag(fromPlayer, "dupe", "trade without owning " .. tostring(itemId))
			return false
		end
		fromInv[itemId] -= amount
		if fromInv[itemId] <= 0 then
			fromInv[itemId] = nil
		end
		local toInv = getInv(toPlayer)
		toInv[itemId] = (toInv[itemId] or 0) + amount
		invPersist(fromPlayer)
		invPersist(toPlayer)
		return true
	end)
end

--// SHOP GUARD

local ShopGuard = {}
local catalog = {}

function ShopGuard.setCatalog(c)
	catalog = c or {}
end

function ShopGuard.buy(player, itemId)
	local entry = catalog[itemId]
	if not entry then
		Logger.flag(player, "shop", "buy unknown item: " .. tostring(itemId))
		return false
	end
	if not InventoryGuard.take(player, entry.currency or "coins", entry.price) then
		return false
	end
	InventoryGuard.give(player, itemId, 1)
	return true
end

--// BEHAVIOR GUARD

local BehaviorGuard = {}
local actionStreams = {}
local actionSessions = {}

function BehaviorGuard.start()
	Players.PlayerRemoving:Connect(function(player)
		actionSessions[player.UserId] = nil
		local prefix = player.UserId .. "\0"
		for k in pairs(actionStreams) do
			if k:sub(1, #prefix) == prefix then
				actionStreams[k] = nil
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
	Logger.log("Aegis v0.2 initialized")
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

function Aegis.buyItem(player, itemId)
	ensureStarted()
	return ShopGuard.buy(player, itemId)
end

function Aegis.recordAction(player, action)
	ensureStarted()
	BehaviorGuard.record(player, action)
end

Aegis.Config = Config
Aegis.Logger = Logger

return Aegis
