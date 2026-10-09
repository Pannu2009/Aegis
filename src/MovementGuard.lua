-- Server-side movement validation.
-- Measures position displacement every checkInterval. Speed hacks, teleports,
-- TweenService tweens and PivotTo calls ALL change position, so one
-- displacement check catches every method. No per-exploit special cases.
--
-- Legitimate scripted movement (spawns, portals, cutscenes) must go through
-- Aegis.teleport() or it will be flagged.

local Players = game:GetService("Players")

local MovementGuard = {}

local cfg
local logger
local last = {} -- [userId] = Vector3
local exemptPos = {} -- [userId] = Vector3 (set by Aegis.teleport)

function MovementGuard.init(c, log)
	cfg = c.movement
	logger = log
	if not cfg.enabled then
		return
	end
	task.spawn(function()
		while true do
			task.wait(cfg.checkInterval)
			MovementGuard.checkAll()
		end
	end)
	Players.PlayerRemoving:Connect(function(player)
		last[player.UserId] = nil
		exemptPos[player.UserId] = nil
	end)
end

function MovementGuard.exempt(player, cframe)
	exemptPos[player.UserId] = cframe.Position
end

function MovementGuard.checkAll()
	local dt = cfg.checkInterval
	for _, player in ipairs(Players:GetPlayers()) do
		local character = player.Character
		local hrp = character and character:FindFirstChild("HumanoidRootPart")
		local humanoid = character and character:FindFirstChildOfClass("Humanoid")
		if hrp and humanoid and humanoid.Health > 0 then
			local uid = player.UserId
			local pos = hrp.Position

			if exemptPos[uid] then
				-- Whitelisted teleport: snap the baseline, skip the check.
				last[uid] = exemptPos[uid]
				exemptPos[uid] = nil
			elseif cfg.ignoreSeated and humanoid.Seated then
				last[uid] = pos
			else
				local state = humanoid:GetState()
				if
					state == Enum.HumanoidStateType.Physics
					or state == Enum.HumanoidStateType.Dead
				then
					-- Game physics or death took over; not the player's doing.
					last[uid] = pos
				else
					local prev = last[uid]
					last[uid] = pos
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
							logger.flag(
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

return MovementGuard
