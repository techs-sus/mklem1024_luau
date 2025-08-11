use libcrux_ml_kem::{
	SHARED_SECRET_SIZE,
	mlkem1024::{self, MlKem1024Ciphertext, MlKem1024KeyPair},
};
use roblox_rs::prelude::*;

/// The #[luau] macro is responsible for generating bindings between Rust and Luau.
/// You can import Luau/Roblox globals using `extern` and simply defining the function signature.
#[luau]
extern "C" {
	fn error(value: &str);
}

struct State {
	pair: MlKem1024KeyPair,
}

#[luau]
pub fn generate(randomness: Vec<u8>) -> u32 {
	assert!(randomness.len() == 64, "must give exactly 64 random bytes");

	let randomness_array: [u8; 64] = randomness.try_into().unwrap();
	let pair = mlkem1024::generate_key_pair(randomness_array);

	Box::into_raw(Box::new(State { pair })) as u32
}

#[luau]
pub fn get_public_key(state: u32) -> Vec<u8> {
	unsafe { (*(state as *mut State)).pair.pk().to_vec() }
}

pub struct Encapsulated {
	ct: [u8; 1568],
	ss: [u8; 32],
}

#[luau]
pub fn encapsulate(state: u32, randomness: Vec<u8>) -> u32 {
	assert!(
		randomness.len() == SHARED_SECRET_SIZE,
		"must give exactly 32 random bytes"
	);

	let randomness_array: [u8; 32] = randomness.try_into().unwrap();

	let (ct, ss) = mlkem1024::encapsulate(
		unsafe { (*(state as *mut State)).pair.public_key() },
		randomness_array,
	);

	Box::into_raw(Box::new(Encapsulated {
		ct: *ct.as_slice(),
		ss,
	})) as u32
}

#[luau]
pub fn get_ciphertext(encapsulated: u32) -> Vec<u8> {
	unsafe { (*(encapsulated as *mut Encapsulated)).ct.to_vec() }
}

#[luau]
pub fn get_shared_secret(encapsulated: u32) -> Vec<u8> {
	unsafe { (*(encapsulated as *mut Encapsulated)).ss.to_vec() }
}

#[luau]
pub fn decapsulate(state: u32, ciphertext: Vec<u8>) -> Vec<u8> {
	let state = unsafe { &*(state as *mut State) };

	assert!(
		ciphertext.len() == 1568,
		"must give exactly 1568 bytes for ciphertext"
	);

	let ciphertext_array: [u8; 1568] = ciphertext.try_into().unwrap();

	mlkem1024::decapsulate(
		state.pair.private_key(),
		&MlKem1024Ciphertext::from(ciphertext_array),
	)
	.to_vec()
}

#[luau]
pub fn free_state(ptr: u32) -> u32 {
	unsafe {
		drop(Box::from_raw(ptr as *mut State));
	};

	0 // prevent build panic
}

#[luau]
pub fn free_encapsulated(ptr: u32) -> u32 {
	unsafe {
		drop(Box::from_raw(ptr as *mut Encapsulated));
	};

	0 // prevent build panic
}
