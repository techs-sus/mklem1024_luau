local exports = require("@self/runtime")
local CSPRNG = require("@self/CSPRNG").New()

if game then --[[ if on roblox, add extra entropy ]]
	local HttpService = game:GetService("HttpService")
	local s = ""
	for i = 0, 64 do
		s ..= HttpService:GenerateGUID(false)
	end

	CSPRNG:GatherEntropy(buffer.fromstring(s))
end

local Module = {}

-- This returns a *mut State. On the WASM side, this contains your public key and private key.
function Module.generate(): number
	return exports.generate(CSPRNG:GetBytes(64))
end

-- This returns the *mut State's public key.
function Module.getPublicKey(state: number): buffer
	return exports.get_public_key(state)
end

-- This returns (ciphertext, ss).
function Module.encapsulate(state: number)
	local encapsulated: number = exports.encapsulate(state, CSPRNG:GetBytes(32))
	local ciphertext = exports.get_ciphertext(encapsulated)
	local ss = exports.get_shared_secret(encapsulated)

	exports.free_encapsulated(encapsulated)

	return ciphertext, ss
end

-- This returns the decapsulated shared secret.
function Module.decapsulate(state: number, ciphertext: buffer): buffer
	return exports.decapsulate(state, ciphertext)
end

-- Call this on a *mut State to free it once you are done using it.
function Module.free(state: number)
	exports.free_state(state)
end

return table.freeze(Module)
