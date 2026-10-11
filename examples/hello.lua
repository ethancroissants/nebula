-- hello.lua — a quick smoke test for Nebula

-- Print to the game console AND back to Nebula's console
print("hello from Nebula! " .. game.PlaceId)

-- Use the bridge functions the hook registers:
nebula.log("bridge is alive")

-- Verify executor identity (script hubs check for this)
local id, ver = identifyexecutor()
print("executor: " .. tostring(id) .. " " .. tostring(ver))
