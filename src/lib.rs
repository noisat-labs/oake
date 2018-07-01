#![feature(non_exhaustive)]

#[macro_use] extern crate failure;
extern crate rand;
extern crate sha3;
extern crate digest;
extern crate subtle;
extern crate curve25519_dalek;

#[macro_use] mod common;
pub mod oake;
pub mod soake;
pub mod roake;

use rand::{ RngCore, CryptoRng };
use subtle::ConstantTimeEq;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;


pub const SECRET_LENGTH: usize = 32;
pub const PUBLIC_LENGTH: usize = 32;
pub const MESSAGE_LENGTH: usize = 32;

pub struct SecretKey(Scalar);
pub struct PublicKey(CompressedRistretto);
pub struct EphemeralKey(Scalar);
pub struct Message(CompressedRistretto);

#[derive(Debug, Fail)]
#[non_exhaustive]
#[must_use]
pub enum Error {
    #[fail(display = "EdwardsPoint decompress error")]
    Decompress,

    #[fail(display = "Not allow zero value")]
    Zero,

    #[fail(display = "Invalid length")]
    Length
}

impl SecretKey {
    #[inline]
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> SecretKey {
        SecretKey(Scalar::random(rng))
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; SECRET_LENGTH] {
        self.0.as_bytes()
    }

    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, Error> {
        if bytes.len() >= SECRET_LENGTH {
            let mut sk = [0; SECRET_LENGTH];
            sk.copy_from_slice(check!(&bytes[..SECRET_LENGTH]));
            Ok(SecretKey(Scalar::from_bits(sk)))
        } else {
            Err(Error::Length)
        }
    }
}

impl PublicKey {
    pub fn from_secret(SecretKey(sk): &SecretKey) -> PublicKey {
        PublicKey((sk * &RISTRETTO_BASEPOINT_TABLE).compress())
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; PUBLIC_LENGTH] {
        self.0.as_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, Error> {
        if bytes.len() >= PUBLIC_LENGTH {
            let mut pk = [0; PUBLIC_LENGTH];
            pk.copy_from_slice(check!(&bytes[..PUBLIC_LENGTH]));
            Ok(PublicKey(CompressedRistretto(pk)))
        } else {
            Err(Error::Length)
        }
    }
}

impl EphemeralKey {
    #[inline]
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> EphemeralKey {
        EphemeralKey(Scalar::random(rng))
    }
}

impl Message {
    pub fn from_ephemeral(EphemeralKey(ek): &EphemeralKey) -> Message {
        Message((ek * &RISTRETTO_BASEPOINT_TABLE).compress())
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; MESSAGE_LENGTH] {
        self.0.as_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Message, Error> {
        if bytes.len() >= MESSAGE_LENGTH {
            let mut msg = [0; MESSAGE_LENGTH];
            msg.copy_from_slice(check!(&bytes[..MESSAGE_LENGTH]));
            Ok(Message(CompressedRistretto(msg)))
        } else {
            Err(Error::Length)
        }
    }
}
