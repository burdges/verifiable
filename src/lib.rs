use core::{
	fmt::Debug,
	marker::PhantomData,
};
use parity_scale_codec::{Decode, Encode, FullCodec, MaxEncodedLen};
use scale_info::*;
use ark_scale::ArkScale;
use bandersnatch_vrfs::{
	SecretKey, PublicKey, RingVrfSignature, ring,
	CanonicalSerialize,CanonicalDeserialize,SerializationError, // ark_serialize::
};
use std::vec::Vec;

// Fixed types:

/// Identifier for an member verifiable by a proof. A member's alias is fixed for any given context.
pub type Alias = [u8; 32];

/// Entropy supplied for the creation of a secret key.
pub type Entropy = [u8; 32];


// The trait. This (alone) must be implemented in its entirely by the Ring-VRF.

/// Trait allowing cryptographic proof of membership of a set with known members under multiple
/// contexts without exposing the underlying member who is proving it and giving an unlinkable
/// deterministic pseudonymic "alias" under each context.
///
/// A value of this type represents a proof. It can be created using the `Self::create` function
/// from the `Self::Secret` value associated with a `Self::Member` value who exists within a set of
/// members identified with a `Self::Members` value. It can later be validated with the
/// `Self::is_valid` function using `self` together with the same information used to crate it
/// (except the secret, of course!).
///
/// A convenience `Receipt` type is provided for typical use cases which bundles the proof along
/// with needed witness information describing the message and alias.
pub trait VerifiableUniqueAlias: Sized
     // Clone + Encode + Decode // + Eq + PartialEq + FullCodec + Debug + TypeInfo + MaxEncodedLen
{
    /*
	/// Alias but unverified. 
    fn unverified_alias(&self, context: &[u8]) -> Alias;
	// /// Remark:  We could limit our VRF to only being a VUF so this method need not
	// /// have a `context` argument.  If you then want randomness then please hash the
	// /// `Alias` with the `context` and include randomness in the `context`. 
	*/

    // Key material

	/// Value identifying a single member. Corresponds to the Public Key.
	type Member: Clone + PartialEq + FullCodec;

	/// Value with which a member can create a proof of membership. Corresponds to the Secret Key.
	type Secret; // Clone

	/// Create a new secret from some particular `entropy`.
	fn new_secret(entropy: &Entropy) -> Self::Secret;

	/// Determine the `Member` value corresponding to a given `Secret`. Basically just the
	/// secret-to-public-key function of the crypto.
	fn member_from_secret(secret: &Self::Secret) -> Self::Member;

    // Ring management

	/// Intermediate value while building a `Self::Members` value. Probably just an unfinished Ring
	/// Root(?)
	type Intermediate; // Clone + PartialEq + FullCodec;

	/// Begin building a `Members` value.
	fn start_members() -> Self::Intermediate;

	/// Introduce a new `Member` into the intermediate value used to build a new `Members` value.
	fn push_member(intermediate: &mut Self::Intermediate, who: Self::Member) -> Result<(),()>;

    /*
    Interface ideas:

	#0. Add as full lists always (Sergey's ring-proof crate)

    #1. Add one by one, but use full list in opening (Gav)

	#2. Edit by index or range, but open by index.  In editing, our user supplies the
	    old members so they can be removed from the KZG, but does this work with our
		Fiat-Shamir?  Yes of course.  This requires retaining more metadata though,
		and doing so correctly, but it fits nicer with on-chain proofs.

    /// If `old.len() < new.len()` then we assume old is padded by the padding point.
	/// If `new.len() < old.len()` then reinsert the padding point into the gap.
	/// In effect, old and new both have length `max(old.len(), new.len())`, with
	/// any unspecified points given by the padding point.
	fn update_members(
		intermediate: &mut Self::Members,
		start: u32,
		old: &[Self::Member],
		new: &[Self::Member],
	);

    #3. Something similar but embed the metadata handling into the type behind the trait.
	    This probabaly just wastes storage proof size on-chain since the index metdata
		cannot be embedded alongside other account data.
 
	Ideally, we'd should keep the prover and verifier interfaces similar.

	Sergey TODO: What do you think of interface #2?

	I'm going with #0 for now just to get something done, as doing anything more
	complex right now feels like a distraction.
    */

    // Verifying

	/// Commitment identifying a particular set of members. Corresponds to the Ring Root.
	type Members; // : Clone + PartialEq + FullCodec;

	/// Consume the `intermediate` value to create a new `Members` value.
	fn finish_members(inter: Self::Intermediate) -> Result<Self::Members, ()>;

	/// Check whether `self` is a valid proof of membership in `members` in the given `context`;
	/// if so, ensure that the member is necessarily associated with `alias` in this `context` and
	/// that they elected to opine `message`.
	fn verify(
		&self,
		members: &Self::Members,
		context: &[u8],
		message: &[u8],
	) -> Result<Alias, ()>;

    // Signing

	/// A partially-created proof. This is created by the `open` function and utilized by the
	/// `create` function.
	type Opening; // : Clone + PartialEq + FullCodec;

	/// First step in creating a proof that `member` exists in a group `members`. The result of this
	/// must be passed into `create` in order to actually create the proof.
	///
	/// This operation uses the potentially large set `members` and as such is expected to be
	/// executed on a device with access to the chain state and is presumably online. The
	/// counterpart operation `create` does not utilize this data. It does require knowledge of the
	/// `Secret` for `member` and as such is practical to conduct on an offline/air-gapped device.
	///
	/// NOTE: We never expect to use this code on-chain; it should be used only in the wallet.
	fn open_members<'a>(
		member: &Self::Member,
		members_iter: impl Iterator<Item = &'a Self::Member>,
	) -> Result<Self::Opening, ()> where Self::Member: 'a;

	/// Create a proof of membership with the `opening` using the given `secret` of the member
	/// of the `opening`.
	///
	/// The proof will be specific to a given `context` (which determines the resultant `Alias`
	/// of the member in a way unlinkable to the member's original identifiaction and aliases
	/// in any other contexts) together with a provided `message` which entirely at the choice
	/// of the individual.
	///
	/// - `context`: The context under which membership is proven. Proofs over different `[u8]`s
	/// are unlinkable.
	///
	/// NOTE: We never expect to use this code on-chain; it should be used only in the wallet.
	fn create(
		opening: Self::Opening,
		secret: &Self::Secret,
		context: &[u8],
		message: &[u8],
	) -> Result<(Self, Alias), ()>;
}


// A hack that moves the .
pub trait Web3SumKZG: 'static {
	fn kzg_bytes() -> &'static [u8];
	fn kzg() -> &'static ring::KZG {
		// TODO: Find a no_std analog.  Check it supports multiple setups.
		use std::sync::OnceLock;
		static CELL: OnceLock<ring::KZG> = OnceLock::new();
		CELL.get_or_init(|| {
			<ring::KZG as CanonicalDeserialize>::deserialize_compressed(Self::kzg_bytes()).unwrap()
		})
	}
}

pub struct Test2e10;

impl Web3SumKZG for Test2e10 {
	fn kzg_bytes() -> &'static [u8] {
		include_bytes!("testing.kzg")
	}
}

#[derive(Encode, Decode)] // Clone, Eq, PartialEq, , Debug, TypeInfo, MaxEncodedLen
pub struct BandersnatchRingVRF<KZG: Web3SumKZG>(
	ArkScale<RingVrfSignature<1>>,
	PhantomData<fn() -> &'static KZG>
);

fn do_input(context: &[u8]) -> bandersnatch_vrfs::VrfInput {
	use bandersnatch_vrfs::IntoVrfInput;
    bandersnatch_vrfs::Message {
		domain: b"Polkadot Fellowship Alias : Input",
		message: context
	}.into_vrf_input()
}

fn do_output(out: [bandersnatch_vrfs::VrfInOut; 1]) -> Alias {
	out[0].vrf_output_bytes(b"Polkadot Fellowship Alias : Output")
} 

impl<KZG: Web3SumKZG> VerifiableUniqueAlias for BandersnatchRingVRF<KZG> {

//	fn unverified_alias(&self) -> Alias {
//		self.0.preoutputs[0]
//	}

	type Secret = SecretKey;
	type Member = [u8; 33];

	fn new_secret(entropy: &Entropy) -> Self::Secret {
		SecretKey::from_seed(entropy)
	}
	fn member_from_secret(secret: &Self::Secret) -> Self::Member {
		secret.to_public().serialize()
	}

	/// TODO: Interface #2 would make this sane.
	type Intermediate = ArkScale<Vec<bandersnatch_vrfs::bandersnatch::SWAffine>>;

	type Members = ArkScale<bandersnatch_vrfs::ring::VerifierKey>;

	fn start_members() -> Self::Intermediate {
		ArkScale(Vec::with_capacity( KZG::kzg().max_keyset_size() ))
	}
	fn push_member(inter: &mut Self::Intermediate, who: Self::Member) -> Result<(),()> {
		let pk = PublicKey::deserialize(&who[..]).map_err(|_| ()) ?;
		inter.0.push(pk.0.0);
		Ok(())
	}
	fn finish_members(inter: Self::Intermediate) -> Result<Self::Members,()> {
		if inter.0.len() > KZG::kzg().max_keyset_size() { return Err(()); }
        // In theory, our ring-prover should pad the KZG but sergey has blatantly
		// insecure padding right now:
		// https://github.com/w3f/ring-proof/blob/master/ring/src/piop/params.rs#L56
        Ok(ArkScale(KZG::kzg().verifier_key(inter.0)))
	}

	fn verify(
		&self,
		members: &Self::Members,
		context: &[u8],
		message: &[u8],
	) -> Result<Alias, ()> {
        let ring_verifier = KZG::kzg().init_ring_verifier(members.0.clone());
 		self.0.0.verify_ring_vrf(message, core::iter::once(do_input(context)), &ring_verifier)
		.map(do_output).map_err(|x| { let r: Result<Alias, _> = Err(x); r.unwrap(); () })
	}

    ///
	type Opening = (u32, ArkScale<bandersnatch_vrfs::ring::ProverKey>);

	fn open_members<'a>(
		myself: &Self::Member,
		members: impl Iterator<Item = &'a Self::Member>,
	) -> Result<Self::Opening, ()>
	where
		Self::Member: 'a,
	{
		let max_len: u32 = KZG::kzg().max_keyset_size().try_into().expect("Impossibly large a KZG, qed");
		let mut i = 0u32;
		let mut me = u32::MAX;
		// #![feature(iterator_try_collect)]
		let mut pks = Vec::with_capacity(members.size_hint().0);
		for member in members {
            if i >= max_len { return Err(()); }
			if myself == member { me = i }
			pks.push(PublicKey::deserialize(&member[..]).map_err(|_| ())?.0.0);
			i += 1;
		}
		if me == u32::MAX { return Err(()); }
		Ok(( me, ArkScale(KZG::kzg().prover_key(pks)) ))
	}

	fn create(
		// Sergey TODO: This should be a borrow but ring-prover still consumes it.
		(me, members): Self::Opening,
		secret: &Self::Secret,
		context: &[u8],
		message: &[u8],
	) -> Result<(Self, Alias), ()> {
		assert!((me as usize) < KZG::kzg().max_keyset_size());
		let io: [_; 1] = [secret.0.vrf_inout(do_input(context))];
        let ring_prover = KZG::kzg().init_ring_prover(members.0, me as usize);
        let signature: RingVrfSignature<1> = secret.sign_ring_vrf(message, &io, &ring_prover);
        Ok(( BandersnatchRingVRF(ArkScale(signature),PhantomData), do_output(io) ))
	}
}


#[cfg(test)]
mod tests {
    use super::*;
    use core::iter;
	use rand_core::{RngCore,OsRng};

    #[test]
	fn create_trusted_setup() {
		let domain_size = 2u32.pow(10);

		let rng = &mut OsRng;
		let mut seed = [0u8;32];
		rng.fill_bytes(&mut seed);

		let kzg = ring::KZG::insecure_kzg_setup(seed, domain_size, rng);

		use std::fs::File;
		use std::io::prelude::*;
		let path = std::path::Path::new("fresh.kzg");
		let mut file = File::create(&path).unwrap_or_else(|why| {
			panic!("couldn't create {}: {}", path.display(), why);
		});
		kzg.serialize_compressed(&mut file).unwrap_or_else(|why| {
			panic!("couldn't write {}: {}", path.display(), why);
		});
	}

    fn random_bytes<const N: usize>() -> [u8; N] {
		let mut entropy = [0u8; N];
		OsRng.fill_bytes(&mut entropy);
		entropy
	}

    type BRVRF = BandersnatchRingVRF<Test2e10>;
	type Member = [u8; 33];

	fn random_keypair() -> (Member,SecretKey) {
		let secret = BRVRF::new_secret(& random_bytes());
		(BRVRF::member_from_secret(&secret), secret)
	}

	fn random_ring() -> Vec<Member> {
		let len = Test2e10::kzg().max_keyset_size();
		// Sergey TODO:  Suppose arbitrary ring sizes below the bound by padding.
		// let len = 2u16.pow(10);
		// let len = u16::from_le_bytes(random_bytes()) % len;
		let mut v = Vec::with_capacity(len as usize);
		for _ in 0..len {
			v.push(random_keypair().0);
		}
		v
	}

	#[test]
	fn send_n_recieve() {
		let (me,secret) = random_keypair();

        // Random ring including me.
		let mut ring = random_ring();
		let idx = ring.len()/2;
		ring[idx] = me;

		let context = random_bytes::<32>();
		let message = random_bytes::<1024>();

        // Sign
		let opening = BRVRF::open_members(&me,ring.iter()).unwrap();
		let (signature,alias1) = BRVRF::create(opening,&secret,&context,&message).unwrap();

        // TODO: serialize signature

        // Verify
		let mut inter = BRVRF::start_members();
		for m in &ring {
			BRVRF::push_member(&mut inter, m.clone()).unwrap();
		}
		let members = BRVRF::finish_members(inter).unwrap();
		let alias2 = signature.verify(&members,&context,&message).unwrap();
		assert_eq!(alias1,alias2);
	}
}




