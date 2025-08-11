--!native
--!optimize 2
local WASM_CTOR = require(script.Parent.wasm)
local WASM_FUNCS = {}
local WASM_EXPORTS = {}
local HEAP, HEAP_ID = {}, 0
local WASM, MEMORY, WASM_STACK
WASM_EXPORTS["generate"] = function(param_0)
	local vec_0 = WASM.func_list.alloc_98dc10e9d72dd56a(64, 1)

	buffer.copy(MEMORY.data, vec_0, param_0)

	local output_0 = WASM.func_list.generate_ff6f4e8e056a6a91(vec_0, 64)
	return output_0
end
WASM_EXPORTS["get_public_key"] = function(param_0)
	local spill_0 = WASM_STACK.value - 8
	WASM_STACK.value = spill_0
	WASM.func_list.get_public_key_3c5999475e503b(spill_0, param_0)
	local output_0 = buffer.readu32(MEMORY.data, spill_0 + 0)
	local output_1 = buffer.readu32(MEMORY.data, spill_0 + 4)
	WASM_STACK.value = spill_0 + 8
	local vector_0 = buffer.create(output_1)

	for index_0 = 0, output_1 - 1 do
		buffer.writeu8(vector_0, index_0, buffer.readu8(MEMORY.data, output_0 + index_0))
	end

	WASM.func_list.free_9f0c05e41871769c(output_0, output_1 * 1, 1)
	return vector_0
end
WASM_EXPORTS["encapsulate"] = function(param_0, param_1)
	local vec_0 = WASM.func_list.alloc_98dc10e9d72dd56a(32, 1)
	buffer.copy(MEMORY.data, vec_0, param_1)
	local output_0 = WASM.func_list.encapsulate_1a0c7475bef4fa4f(param_0, vec_0, 32)
	return output_0
end
WASM_EXPORTS["get_ciphertext"] = function(param_0)
	local spill_0 = WASM_STACK.value - 8
	WASM_STACK.value = spill_0
	WASM.func_list.get_ciphertext_d5014ed1f5bb242b(spill_0, param_0)
	local output_0 = buffer.readu32(MEMORY.data, spill_0 + 0)
	local output_1 = buffer.readu32(MEMORY.data, spill_0 + 4)
	WASM_STACK.value = spill_0 + 8
	local vector_0 = buffer.create(output_1)

	for index_0 = 0, output_1 - 1 do
		buffer.writeu8(vector_0, index_0, buffer.readu8(MEMORY.data, output_0 + index_0))
	end

	WASM.func_list.free_9f0c05e41871769c(output_0, output_1 * 1, 1)
	return vector_0
end
WASM_EXPORTS["get_shared_secret"] = function(param_0)
	local spill_0 = WASM_STACK.value - 8
	WASM_STACK.value = spill_0
	WASM.func_list.get_shared_secret_9429be60f531f740(spill_0, param_0)
	local output_0 = buffer.readu32(MEMORY.data, spill_0 + 0)
	local output_1 = buffer.readu32(MEMORY.data, spill_0 + 4)
	WASM_STACK.value = spill_0 + 8
	local vector_0 = buffer.create(output_1)

	for index_0 = 0, output_1 - 1 do
		buffer.writeu8(vector_0, index_0, buffer.readu8(MEMORY.data, output_0 + index_0))
	end

	WASM.func_list.free_9f0c05e41871769c(output_0, output_1 * 1, 1)
	return vector_0
end
WASM_EXPORTS["decapsulate"] = function(param_0, param_1)
	local vec_0 = WASM.func_list.alloc_98dc10e9d72dd56a(1568, 1)
	buffer.copy(MEMORY.data, vec_0, param_1)
	local spill_0 = WASM_STACK.value - 8
	WASM_STACK.value = spill_0
	WASM.func_list.decapsulate_78cdd3c508f73eaf(spill_0, param_0, vec_0, 1568)
	local output_0 = buffer.readu32(MEMORY.data, spill_0 + 0)
	local output_1 = buffer.readu32(MEMORY.data, spill_0 + 4)
	WASM_STACK.value = spill_0 + 8
	local vector_0 = buffer.create(output_1)

	for index_0 = 0, output_1 - 1 do
		buffer.writeu8(vector_0, index_0, buffer.readu8(MEMORY.data, output_0 + index_0))
	end

	WASM.func_list.free_9f0c05e41871769c(output_0, output_1 * 1, 1)
	return vector_0
end
WASM_EXPORTS["free_state"] = function(param_0)
	local output_0 = WASM.func_list.free_state_d75383ca296286e7(param_0)
	return output_0
end
WASM_EXPORTS["free_encapsulated"] = function(param_0)
	local output_0 = WASM.func_list.free_encapsulated_85436f9a7caa0d7b(param_0)
	return output_0
end
WASM = WASM_CTOR({ luau = { func_list = WASM_FUNCS } })
MEMORY = WASM.memory_list.memory
WASM_STACK = WASM.global_list.__stack_pointer
return WASM_EXPORTS
