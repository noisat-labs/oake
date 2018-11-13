use sha3::{ Sha3_512, Shake256 };
use digest::{ Input, ExtendableOutput, XofReader };
use curve25519_dalek::scalar::Scalar;
use ::{ SecretKey, PublicKey, EphemeralKey, Message, Error };


pub fn send<ID: AsRef<str>>(
    (ref ida, SecretKey(a), PublicKey(aa)): (ID, &SecretKey, &PublicKey),
    (ref idb, PublicKey(bb)): (ID, &PublicKey),
    (EphemeralKey(x), Message(xx)): (&EphemeralKey, &Message),
    Message(yy): &Message,
    shared: &mut [u8]
) -> Result<(), Error> {
    let mut hasher = Sha3_512::default();
    hasher.input(ida.as_ref().as_bytes());
    hasher.input(aa.as_bytes());
    hasher.input(idb.as_ref().as_bytes());
    hasher.input(bb.as_bytes());
    hasher.input(xx.as_bytes());
    hasher.input(yy.as_bytes());
    let e = Scalar::from_hash(hasher);

    let bb = decompress!(bb);
    let yy = decompress!(yy);

    let k = bb * x + yy * (a + e * x);

    let mut hasher = Shake256::default();
    hasher.input(k.compress().as_bytes());
    hasher.xof_result().read(shared);

    Ok(())
}

pub fn recv<ID: AsRef<str>>(
    (ref idb, SecretKey(b), PublicKey(bb)): (ID, &SecretKey, &PublicKey),
    (ref ida, PublicKey(aa)): (ID, &PublicKey),
    (EphemeralKey(y), Message(yy)): (&EphemeralKey, &Message),
    Message(xx): &Message,
    shared: &mut [u8]
) -> Result<(), Error> {
    let mut hasher = Sha3_512::default();
    hasher.input(ida.as_ref().as_bytes());
    hasher.input(aa.as_bytes());
    hasher.input(idb.as_ref().as_bytes());
    hasher.input(bb.as_bytes());
    hasher.input(xx.as_bytes());
    hasher.input(yy.as_bytes());
    let e = Scalar::from_hash(hasher);

    let aa = decompress!(aa);
    let xx = decompress!(xx);

    let k = aa * y + xx * (b + e * y);

    let mut hasher = Shake256::default();
    hasher.input(k.compress().as_bytes());
    hasher.xof_result().read(shared);

    Ok(())
}


#[test]
fn test_soake() {
    use rand::thread_rng;

    let mut rng = thread_rng();

    let a_name = "alice@oake.ene";
    let a_sk = SecretKey::generate(&mut rng);
    let a_pk = PublicKey::from_secret(&a_sk);
    let a_ek = EphemeralKey::generate(&mut rng);
    let a_epk = Message::from_ephemeral(&a_ek);
    let mut a_key = [0; 32];

    let b_name = "bob@oake.ene";
    let b_sk = SecretKey::generate(&mut rng);
    let b_pk = PublicKey::from_secret(&b_sk);
    let b_ek = EphemeralKey::generate(&mut rng);
    let b_epk = Message::from_ephemeral(&b_ek);
    let mut b_key = [0; 32];

    send(
        (a_name, &a_sk, &a_pk),
        (b_name, &b_pk),
        (&a_ek, &a_epk),
        &b_epk,
        &mut a_key
    ).unwrap();

    recv(
        (b_name, &b_sk, &b_pk),
        (a_name, &a_pk),
        (&b_ek, &b_epk),
        &a_epk,
        &mut b_key
    ).unwrap();

    assert_ne!(a_key, [0; 32]);
    assert_eq!(a_key, b_key);
}
