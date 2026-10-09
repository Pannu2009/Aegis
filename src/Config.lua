-- Aegis default configuration.
-- Override anything via Aegis.configure() or Aegis.init().

return {
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
