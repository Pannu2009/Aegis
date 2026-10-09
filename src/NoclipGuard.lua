-- Noclip detection, two layers:
--   1. Path raycast: segment from last position to current. If it crosses
--      solid (CanCollide) geometry, the player moved through a wall.
--   2. Inside-part check: shrunken bounding box at the character; if it
--      overlaps solid geometry, the player is embedded in a wall.
-- Floor-like hits (normal pointing up) are ignored to avoid stair false-positives.

local Players = game:GetService("Players")
local Workspace = game:GetService("Workspace")

local NoclipGuard = {}

local cfg
local logger
local last = {} -- [userId] = Vector3
local skipNext = {} -- [userId] = true (set by Aegis.teleport)

function NoclipGuard.init(c, log)
	cfg = c.noclip
	logger = log
	if not cfg.enabled then
		return
	end
	task.spawn(function()
		while true do
			task.wait(cfg.checkInterval)
			NoclipGuard.checkAll()
		end
	end)
	Players.PlayerRemoving:Connect(function(player)
		last[player.UserId] = nil
		skipNext[player.UserId] = nil
	end)
end

function NoclipGuard.exempt(player)
	skipNext[player.UserId] = true
end

local function rayParams(character)
	local p = RaycastParams.new()
	p.FilterType = Enum.RaycastFilterType.Exclude
	p.FilterDescendantsInstances = { character }
	return p
end

function NoclipGuard.checkAll()
	for _, player in ipairs(Players:GetPlayers()) do
		local character = player.Character
		local hrp = character and character:FindFirstChild("HumanoidRootPart")
		local humanoid = character and character:FindFirstChildOfClass("Humanoid")
		if hrp and humanoid and humanoid.Health > 0 then
			local uid = player.UserId
			local pos = hrp.Position

			if skipNext[uid] then
				skipNext[uid] = nil
				last[uid] = pos
			elseif cfg.ignoreSeated and humanoid.Seated then
				last[uid] = pos
			else
				local prev = last[uid]
				last[uid] = pos
				if prev and (pos - prev).Magnitude > 1 then
					-- Layer 1: did the path cross solid geometry?
					local dir = pos - prev
					local hit = Workspace:Raycast(prev, dir, rayParams(character))
					if hit and hit.Instance.CanCollide and hit.Normal.Y < 0.7 then
						logger.flag(player, "noclip", "crossed " .. hit.Instance:GetFullName())
					else
						-- Layer 2: embedded inside solid geometry?
						local overlap = OverlapParams.new()
						overlap.FilterType = Enum.RaycastFilterType.Exclude
						overlap.FilterDescendantsInstances = { character }
						local parts =
							Workspace:GetPartBoundsInBox(hrp.CFrame, hrp.Size * 0.5, overlap)
						for _, part in ipairs(parts) do
							if part.CanCollide and part:IsDescendantOf(Workspace) then
								logger.flag(player, "noclip", "inside " .. part:GetFullName())
								break
							end
						end
					end
				end
			end
		end
	end
end

return NoclipGuard
