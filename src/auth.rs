//! Room admission, and the identity of a room opened by name.
//!
//! This layer is **not encryption** — iroh already encrypts every connection end to end
//! with QUIC/TLS. What the QUIC handshake proves about the other side depends on how the
//! room was reached:
//!
//! * **By invite code.** The code is the coordinator's public key, so QUIC verifies the
//!   joiner reached exactly the machine that printed it. The password's only job is to say
//!   "not everyone who gets hold of this code may come in".
//! * **By room name and passphrase.** The coordinator's secret key is *derived* from the
//!   two, so QUIC proves much less: only that the other side knows the passphrase, not
//!   which machine it is. Anyone holding the passphrase can open a rival room under the
//!   same name, or publish their own addresses under its key while the real host is
//!   running. That is the price of an invite that can be said out loud.
//!
//! Either way the password never travels over the wire. Each side stretches it once with
//! Argon2id into an admission key; the coordinator sends a random nonce and the joiner
//! answers with a keyed BLAKE2b MAC of it. The nonce is fresh on every connection, so a
//! captured proof cannot be replayed — and the coordinator does no Argon2 work per
//! connection attempt, which would otherwise be a cheap way to burn its CPU.

use anyhow::{Result, anyhow, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use blake2::Blake2bMac;
use blake2::digest::Mac;
use blake2::digest::consts::U32;
use iroh::SecretKey;
use rand::Rng;
use subtle::{Choice, ConstantTimeEq};

use crate::proto::PeerId;

pub type Nonce = [u8; 16];
pub type Proof = [u8; 32];

/// The longest room name, in characters.
///
/// Kept under the invite code's 52 so that `tincan join` can never mistake a room name
/// for a code.
pub const MAX_ROOM_CHARS: usize = 48;

/// Argon2id cost `(memory KiB, passes, lanes)` for a room opened by name.
///
/// Pinned rather than taken from `Params::default()`: these numbers are part of every
/// room's address, and a library changing its defaults would silently move them all.
/// Heavier than the invite path's, because anyone can compute the key for a guessed
/// ("lobby", "123456") and look it up — this cost is the only thing in the way.
const ROOM_COST: (u32, u32, u32) = (64 * 1024, 3, 1);
/// Argon2id cost for the invite path, where only the coordinator ever sees a proof.
const INVITE_COST: (u32, u32, u32) = (19 * 1024, 2, 1);

/// Salt prefixes. They keep the two derivations apart, and give Argon2 the eight bytes of
/// salt it insists on even for a room called "lan".
const ROOM_SALT: &[u8] = b"tincan/room/v1\0";
const INVITE_SALT: &[u8] = b"tincan/invite/v1\0";

/// BLAKE2b personalisations, one per thing a key is used for (16 bytes at most).
const IDENTITY: &[u8] = b"tincan/identity";
const ADMIT: &[u8] = b"tincan/admit";
const PROOF: &[u8] = b"tincan/proof";

/// The key a password is stretched into. Proofs are MACs under it.
#[derive(Clone)]
pub struct Key([u8; 32]);

impl Key {
    /// The admission key for a room reached by its invite code.
    ///
    /// Salted with the coordinator's public key: the joiner already has it from the code,
    /// and it keeps a key stretched for one room from being any use against another.
    /// Passwordless rooms use the empty string, so that there is a single path through
    /// the handshake and no "is there a password" branch leaks into the protocol.
    pub fn for_invite(password: &str, coordinator: &PeerId) -> Result<Self> {
        let master = stretch(&fold(password), INVITE_SALT, &coordinator.0, INVITE_COST)?;
        Ok(Self(mac(&master, ADMIT, &[])))
    }
}

/// Everything a room name and passphrase derive to.
pub struct RoomSecret {
    identity: SecretKey,
    key: Key,
}

impl RoomSecret {
    /// Derives the room's identity and admission key.
    ///
    /// The Ed25519 secret and the admission key are separate BLAKE2b subkeys of one
    /// Argon2id master, so the key proofs are made with is never the key the endpoint
    /// signs with.
    pub fn derive(room: &str, passphrase: &str) -> Result<Self> {
        let room = normalize_room(room)?;
        let passphrase = fold(passphrase);
        ensure!(
            !passphrase.is_empty(),
            "a room opened by name needs a passphrase"
        );

        let master = stretch(&passphrase, ROOM_SALT, room.as_bytes(), ROOM_COST)?;
        Ok(Self {
            identity: SecretKey::from_bytes(&mac(&master, IDENTITY, &[])),
            key: Key(mac(&master, ADMIT, &[])),
        })
    }

    /// The coordinator's secret key: the host binds with it.
    pub fn identity(&self) -> SecretKey {
        self.identity.clone()
    }

    /// The coordinator's public identity: the joiner connects to it.
    pub fn coordinator(&self) -> PeerId {
        PeerId(*self.identity.public().as_bytes())
    }

    /// The key a joiner proves itself with.
    pub fn key(&self) -> &Key {
        &self.key
    }
}

/// What the coordinator checks proofs against.
pub struct Admission {
    keys: Vec<Key>,
}

impl Admission {
    /// A room reached only by its invite code.
    pub fn invite(password: &str, coordinator: &PeerId) -> Result<Self> {
        Ok(Self {
            keys: vec![Key::for_invite(password, coordinator)?],
        })
    }

    /// A room opened by name. It admits the invite-code key for the same passphrase too:
    /// the code still reaches this room, and whoever uses it knows the coordinator's key
    /// but not necessarily the room name.
    pub fn room(secret: &RoomSecret, passphrase: &str) -> Result<Self> {
        Ok(Self {
            keys: vec![
                secret.key.clone(),
                Key::for_invite(passphrase, &secret.coordinator())?,
            ],
        })
    }

    /// Verifies a proof in constant time. Every key is tried even after one matches, so
    /// the timing does not say which way in was used.
    pub fn admits(&self, nonce: &Nonce, presented: &Proof) -> bool {
        self.keys
            .iter()
            .fold(Choice::from(0), |matched, key| {
                matched | proof(key, nonce).ct_eq(presented)
            })
            .into()
    }
}

pub fn random_nonce() -> Nonce {
    let mut nonce = [0u8; 16];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

/// The joiner's answer to a challenge.
pub fn proof(key: &Key, nonce: &Nonce) -> Proof {
    mac(&key.0, PROOF, nonce)
}

/// Normalizes a room name the way the derivation sees it.
pub fn normalize_room(name: &str) -> Result<String> {
    let name = fold(name);
    ensure!(!name.is_empty(), "a room name cannot be empty");
    ensure!(
        name.chars().count() <= MAX_ROOM_CHARS,
        "a room name can be at most {MAX_ROOM_CHARS} characters"
    );
    Ok(name)
}

/// Forgives what cannot be heard: case, surrounding space, and the choice of separator.
///
/// "Chestnut Ferry" and "chestnut-ferry" are one passphrase, because someone reading it
/// down the phone has no way to say which of the two they meant.
fn fold(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut gap = false;
    for c in text.trim().chars() {
        if c.is_whitespace() || c == '-' || c == '_' {
            gap = true;
            continue;
        }
        if gap && !out.is_empty() {
            out.push('-');
        }
        gap = false;
        out.extend(c.to_lowercase());
    }
    out
}

fn stretch(secret: &str, domain: &[u8], context: &[u8], cost: (u32, u32, u32)) -> Result<[u8; 32]> {
    let (memory, passes, lanes) = cost;
    let params = Params::new(memory, passes, lanes, Some(32))
        .map_err(|e| anyhow!("invalid key derivation parameters: {e}"))?;
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(secret.as_bytes(), &[domain, context].concat(), &mut out)
        .map_err(|e| anyhow!("key derivation failed: {e}"))?;
    Ok(out)
}

fn mac(key: &[u8; 32], persona: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = Blake2bMac::<U32>::new_with_salt_and_personal(key, &[], persona)
        .expect("a 32-byte key and a short persona are within BLAKE2b's limits");
    mac.update(message);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(seed: u8) -> PeerId {
        PeerId([seed; 32])
    }

    fn invite(password: &str) -> Admission {
        Admission::invite(password, &peer(1)).unwrap()
    }

    fn answer(password: &str, nonce: &Nonce) -> Proof {
        proof(&Key::for_invite(password, &peer(1)).unwrap(), nonce)
    }

    #[test]
    fn correct_password_verifies() {
        let nonce = random_nonce();
        assert!(invite("secret123").admits(&nonce, &answer("secret123", &nonce)));
    }

    #[test]
    fn wrong_password_is_rejected() {
        let nonce = random_nonce();
        let p = answer("secret123", &nonce);
        assert!(!invite("secret124").admits(&nonce, &p));
        assert!(!invite("").admits(&nonce, &p));
    }

    /// A captured proof must be useless on another connection.
    #[test]
    fn proof_is_bound_to_its_nonce() {
        let first = random_nonce();
        let second = random_nonce();
        assert_ne!(first, second, "the nonce must be fresh every time");

        let room = invite("same-password");
        let p = answer("same-password", &first);
        assert!(room.admits(&first, &p));
        assert!(!room.admits(&second, &p), "replay must be blocked");
    }

    #[test]
    fn passwordless_rooms_work_through_the_same_path() {
        let nonce = random_nonce();
        let p = answer("", &nonce);
        assert!(invite("").admits(&nonce, &p));
        assert!(!invite("a-password").admits(&nonce, &p));
    }

    /// A key stretched for one coordinator must not open another.
    #[test]
    fn invite_keys_are_bound_to_their_coordinator() {
        let nonce = [3u8; 16];
        let p = proof(&Key::for_invite("abc", &peer(1)).unwrap(), &nonce);
        assert!(
            Admission::invite("abc", &peer(1))
                .unwrap()
                .admits(&nonce, &p)
        );
        assert!(
            !Admission::invite("abc", &peer(2))
                .unwrap()
                .admits(&nonce, &p)
        );
    }

    /// The point of this test is the multi-byte password — keep it non-ASCII.
    #[test]
    fn non_ascii_passwords_are_supported() {
        let nonce = random_nonce();
        assert!(invite("パスワードäöü").admits(&nonce, &answer("パスワードäöü", &nonce)));
        assert!(invite("ÄÖÜ").admits(&nonce, &answer("äöü", &nonce)));
    }

    #[test]
    fn what_cannot_be_heard_is_forgiven() {
        assert_eq!(
            fold("  Chestnut Ferry\tLens__moss "),
            "chestnut-ferry-lens-moss"
        );
        assert_eq!(fold("chestnut--ferry"), "chestnut-ferry");
        assert_eq!(fold("-lobby-"), "lobby");
        assert_eq!(fold(""), "");
    }

    /// Both sides must land on the same address from the same two words, however they
    /// were typed.
    #[test]
    fn room_derivation_is_deterministic_and_forgiving() {
        let host = RoomSecret::derive("lobby", "chestnut-ferry-lens-moss").unwrap();
        let joiner = RoomSecret::derive(" Lobby", "Chestnut Ferry Lens Moss").unwrap();
        assert_eq!(host.coordinator(), joiner.coordinator());
        assert_eq!(host.key().0, joiner.key().0);
    }

    #[test]
    fn room_and_passphrase_both_move_the_address() {
        let base = RoomSecret::derive("lobby", "chestnut-ferry-lens-moss").unwrap();
        let other_room = RoomSecret::derive("lobby2", "chestnut-ferry-lens-moss").unwrap();
        let other_pass = RoomSecret::derive("lobby", "chestnut-ferry-lens-mess").unwrap();
        assert_ne!(base.coordinator(), other_room.coordinator());
        assert_ne!(base.coordinator(), other_pass.coordinator());
        assert_ne!(base.key().0, other_pass.key().0);
    }

    /// The signing key and the proof key come from one master but must not be the same
    /// bytes, and neither may be the invite path's key.
    #[test]
    fn room_keys_are_separated_by_purpose() {
        let room = RoomSecret::derive("lan", "chestnut-ferry-lens-moss").unwrap();
        assert_ne!(room.identity().to_bytes(), room.key().0);
        let invite = Key::for_invite("chestnut-ferry-lens-moss", &room.coordinator()).unwrap();
        assert_ne!(invite.0, room.key().0);
    }

    /// These bytes are the address of every room called "lobby" with this passphrase. If
    /// this test fails, rooms opened by an older tincan can no longer be found.
    #[test]
    fn room_identity_is_pinned() {
        let room = RoomSecret::derive("lobby", "chestnut-ferry-lens-moss").unwrap();
        assert_eq!(room.coordinator().to_string(), PINNED_LOBBY);
    }
    const PINNED_LOBBY: &str = "e644ff027b6d37039875fa117a32ca09f077e5e823b2bb03f29c2b2e869d2abc";

    #[test]
    fn a_named_room_admits_both_ways_in_and_nothing_else() {
        let room = RoomSecret::derive("lobby", "chestnut-ferry-lens-moss").unwrap();
        let admission = Admission::room(&room, "chestnut-ferry-lens-moss").unwrap();
        let nonce = random_nonce();

        assert!(
            admission.admits(&nonce, &proof(room.key(), &nonce)),
            "by name"
        );
        let by_code = Key::for_invite("chestnut-ferry-lens-moss", &room.coordinator()).unwrap();
        assert!(
            admission.admits(&nonce, &proof(&by_code, &nonce)),
            "by code"
        );
        let wrong = Key::for_invite("chestnut-ferry-lens-mess", &room.coordinator()).unwrap();
        assert!(
            !admission.admits(&nonce, &proof(&wrong, &nonce)),
            "wrong passphrase"
        );
    }

    #[test]
    fn empty_or_oversized_input_is_refused() {
        assert!(RoomSecret::derive("", "chestnut-ferry-lens-moss").is_err());
        assert!(RoomSecret::derive("  - ", "chestnut-ferry-lens-moss").is_err());
        assert!(RoomSecret::derive("lobby", "   ").is_err());
        assert!(normalize_room(&"a".repeat(MAX_ROOM_CHARS)).is_ok());
        assert!(normalize_room(&"a".repeat(MAX_ROOM_CHARS + 1)).is_err());
    }
}
