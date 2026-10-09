-- Aegis logging: flags, strikes, kicks, optional Discord webhook.

local HttpService = game:GetService("HttpService")

local Logger = {}

local config
local strikes = {} -- ["userId:category"] = count

function Logger.init(cfg)
	config = cfg
end

local function sendWebhook(message)
	if not config or config.discordWebhook == "" then
		return
	end
	task.spawn(function()
		pcall(function()
			HttpService:PostAsync(
				config.discordWebhook,
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
	local msg = string.format(
		"FLAG %s (%d) [%s] %s (strike %d)",
		player.Name,
		player.UserId,
		category,
		detail or "",
		count
	)
	Logger.log(msg)
	if config.kickOnDetect and count >= config.flagThreshold then
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

return Logger
