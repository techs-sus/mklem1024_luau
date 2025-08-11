local Module: typeof(require("../library")) = require(script.Parent.Library)

local start = os.clock()
local state = Module.generate()
local publicKey = Module.getPublicKey(state)

local ct, ss = Module.encapsulate(state)
local ss2 = Module.decapsulate(state, ct)

assert(buffer.tostring(ss) == buffer.tostring(ss2), "mlkem1024 roundtrip should work")
assert(buffer.len(ct) == 1568, "mlkem1024 ciphertext size should be 1568 bytes")
assert(buffer.len(publicKey) == 1568, "mlkem1024 public key size should be 1568 bytes")

print("took", os.clock() - start, "seconds to test implementation")
