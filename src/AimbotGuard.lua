-- Statistical aimbot detection. Two heuristics:
--   1. Snap: impossible angle change between consecutive shots.
--   2. Lock: inhuman tracking consistency over many shots.
--
-- Flag-only BY DESIGN. Legitimately cracked players trip naive heuristics,
-- so this logs for review and never auto-kicks. Feed it via
-- Aegis.reportShot(player, aimDirection), or set trackAim in a
-- secured remote's schema to auto-feed a Vector3 argument.

local AimbotGuard = {}

local cfg
local logger
local history = {} -- [userId] = { {dir = Vector3, t = number}, ... }
local MAX_HISTORY = 30

function AimbotGuard.init(c, log)
	cfg = c.aimbot
	logger = log
end

local function angleBetween(a, b)
	return math.deg(math.acos(math.clamp(a:Dot(b), -1, 1)))
end

function AimbotGuard.trackShot(player, aimDir)
	if not cfg.enabled then
		return
	end
	if typeof(aimDir) ~= "Vector3" or aimDir.Magnitude < 0.001 then
		return
	end

	local uid = player.UserId
	local h = history[uid]
	if not h then
		h = {}
		history[uid] = h
	end

	local now = os.clock()
	local dir = aimDir.Unit

	if #h > 0 then
		local prev = h[#h]
		local snap = angleBetween(prev.dir, dir)
		if snap > cfg.maxSnapDegrees and (now - prev.t) < 1 then
			logger.warn(
				player,
				"aimbot",
				string.format("snap %.0f deg in %.2fs", snap, now - prev.t)
			)
		end
	end

	table.insert(h, { dir = dir, t = now })
	if #h > MAX_HISTORY then
		table.remove(h, 1)
	end

	-- Inhuman steadiness: 10 consecutive shot pairs all under 1.5 degrees
	-- apart while firing means the aim is not being driven by a human hand.
	if #h >= 11 then
		local steady = 0
		for i = #h - 9, #h do
			if angleBetween(h[i - 1].dir, h[i].dir) < 1.5 then
				steady += 1
			end
		end
		if steady >= 10 then
			logger.warn(player, "aimbot", "inhuman tracking consistency")
			history[uid] = {}
		end
	end
end

return AimbotGuard
