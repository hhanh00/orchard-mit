use std::io::{Read, Write};
use rand_chacha::ChaChaRng;
use rand_chacha::rand_core::SeedableRng;
use orchard::builder::Builder;
use orchard::Bundle;
use orchard::bundle::{Authorized, Flags};
use orchard::circuit::{ProvingKey, VerifyingKey};
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use orchard::tree::MerkleHashOrchard;
use orchard::value::NoteValue;
use incrementalmerkletree::Hashable;

fn build() {
    let pk = ProvingKey::build();

    let mut pk_file = std::fs::File::create("orchard.params").unwrap();
    let mut buffer = bincode::serialize(&pk).unwrap();
    pk_file.write_all(&mut buffer).unwrap();
    println!("{}", buffer.len());
}

fn main() {
    let mut rng = ChaChaRng::seed_from_u64(0);
    let pk_bytes = std::fs::read("orchard.params").unwrap();
    let pk: ProvingKey = bincode::deserialize(&pk_bytes).unwrap();

    let vk = VerifyingKey::build();

    let sk = SpendingKey::from_bytes([0; 32]).unwrap();
    let fvk = FullViewingKey::from(&sk);
    let address = fvk.address_at(0u32, Scope::External);

    let anchor = MerkleHashOrchard::empty_root(32.into()).into();
    let mut builder = Builder::new(Flags::from_parts(true, true), anchor);
    builder.add_recipient(None, address, NoteValue::from_raw(10000), None).unwrap();
    let unauthorized: Bundle<_, i64> = builder.build(&mut rng).unwrap();
    let sig_hash: [u8; 32] = unauthorized.commitment().into();
    let authorized: Bundle<Authorized, i64> = unauthorized
        .create_proof(&pk, &mut rng).unwrap()
        .prepare(&mut rng, sig_hash)
        .finalize().unwrap();

    authorized.verify_proof(&vk).unwrap();
    let bvk = authorized.binding_validating_key();
    let sighash: [u8; 32] = authorized.commitment().into();
    for action in authorized.actions() {
        assert!(action.rk().verify(&sighash, action.authorization()).is_ok());
    }
    bvk.verify(&sighash, authorized.authorization().binding_signature()).unwrap();
    println!("bundle verified");

}