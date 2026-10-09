-- Validates RemoteEvent traffic server-side:
-- arg types, per-player rate limits, arg size caps (anti-crasher).
-- Invalid calls never reach game logic.

local RemoteValidator = {}

local config
local logger
local AimbotGuard
local buckets = {} -- ["userId\0RemoteName"] = { timestamps }

function RemoteValidator.init(cfg, log)
	config = cfg
	logger = log
	AimbotGuard = require(script.Parent.AimbotGuard)
end

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
	for _, t in ipairs(buckets[key] or {}) do
		if now - t < perSec then
			table.insert(kept, t)
		end
	end
	buckets[key] = kept
	if #kept >= maxCalls then
		return false
	end
	table.insert(kept, now)
	return true
end

local function resolveSchema(remote, override)
	local schema = {
		args = {},
		rateLimit = config.remoteDefaults.rateLimit,
		maxArgSize = config.remoteDefaults.maxArgSize,
		trackAim = false,
		aimArg = 1,
	}
	local per = config.remotes[remote.Name]
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
			logger.flag(player, "remote-spam", remote.Name)
			return
		end

		if #args > #schema.args then
			logger.flag(player, "remote-args", remote.Name .. ": too many args")
			return
		end

		for i, expected in ipairs(schema.args) do
			local v = args[i]
			if v == nil and expected ~= "nil" then
				logger.flag(player, "remote-args", remote.Name .. ": missing arg " .. i)
				return
			end
			if not typeOk(v, expected) then
				logger.flag(
					player,
					"remote-args",
					string.format("%s: arg %d expected %s, got %s", remote.Name, i, expected, typeof(v))
				)
				return
			end
			if not sizeOk(v, schema.maxArgSize) then
				logger.flag(player, "remote-crasher", remote.Name .. ": oversized arg " .. i)
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
			logger.log("handler error in " .. remote.Name .. ": " .. tostring(err))
		end
	end)
end

return RemoteValidator
