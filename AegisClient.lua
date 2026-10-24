--// AegisClient — optional companion LocalScript for Aegis v0.5.
--// Put this in StarterPlayerScripts. It pings the server every
--// 20 seconds so the server knows the client is alive.
--//
--// HONEST LIMIT: an exploiter can delete any LocalScript,
--// including this one. A missing ping is NEVER evidence on its
--// own -- it only supports what the server-side guards already
--// saw. The server stays the truth.
--// Server side: Aegis.initClientCompanion() creates the
--// AegisClientPing remote; Aegis.getClientStatus(player)
--// returns seconds since the last ping (nil = never pinged).

local ReplicatedStorage = game:GetService("ReplicatedStorage")

local remotes = ReplicatedStorage:WaitForChild("Remotes", 10)
local ping = remotes and remotes:WaitForChild("AegisClientPing", 10)

if ping then
	while true do
		task.wait(20)
		pcall(function()
			ping:FireServer()
		end)
	end
end
