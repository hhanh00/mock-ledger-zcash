//! Software implementation of the Official Ledger PCZT subset used by zkool.
//! Automatically approves transactions; only suitable for test seeds.
use anyhow::{anyhow, bail, ensure, Result};
use byteorder::{BigEndian as BE, LittleEndian as LE, ReadBytesExt};
use ff::PrimeField;
use orchard::keys::{SpendAuthorizingKey, SpendingKey};
use pasta_curves::pallas;
use secp256k1::{Message, PublicKey, Secp256k1};
use std::io::{Cursor, Read};
use zcash_transparent::address::TransparentAddress;
use zcash_transparent::keys::{AccountPrivKey, NonHardenedChildIndex, TransparentKeyScope};

const HARDENED: u32 = 1 << 31;
const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_ITEMS: usize = 255;

fn hash(personal: &[u8; 16], parts: &[&[u8]]) -> [u8; 32] {
    let mut state = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(personal)
        .to_state();
    for part in parts {
        state.update(part);
    }
    state.finalize().as_bytes().try_into().unwrap()
}

struct Reader<'a>(Cursor<&'a [u8]>);
impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self(Cursor::new(data))
    }
    fn bytes<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut b = [0; N];
        self.0.read_exact(&mut b)?;
        Ok(b)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.0.read_u8()?)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(self.0.read_u32::<LE>()?)
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(self.0.read_u64::<LE>()?)
    }
    fn optional(&mut self, default: u32) -> Result<u32> {
        match self.u8()? {
            0 => Ok(default),
            1 => self.u32(),
            _ => bail!("invalid option tag"),
        }
    }
    fn compact(&mut self) -> Result<usize> {
        let n = match self.u8()? {
            253 => {
                let n = self.0.read_u16::<LE>()? as u64;
                ensure!(n >= 253, "noncanonical length");
                n
            }
            254 => {
                let n = self.u32()? as u64;
                ensure!(n > 65535, "noncanonical length");
                n
            }
            255 => {
                let n = self.u64()?;
                ensure!(n > u32::MAX as u64, "noncanonical length");
                n
            }
            n => n as u64,
        };
        ensure!(n <= MAX_BYTES as u64, "length exceeds mock limit");
        Ok(n as usize)
    }
    fn count(&mut self) -> Result<usize> {
        let n = self.compact()?;
        ensure!(n <= MAX_ITEMS, "too many items");
        Ok(n)
    }
    fn vector(&mut self) -> Result<Vec<u8>> {
        let n = self.compact()?;
        let mut b = vec![0; n];
        self.0.read_exact(&mut b)?;
        Ok(b)
    }
    fn path(&mut self) -> Result<Vec<u32>> {
        let n = self.u8()?;
        ensure!(n <= 5, "invalid derivation path");
        (0..n).map(|_| Ok(self.0.read_u32::<BE>()?)).collect()
    }
    fn done(&self) -> Result<()> {
        ensure!(
            self.0.position() as usize == self.0.get_ref().len(),
            "trailing data"
        );
        Ok(())
    }
}
fn script_bytes(script: &[u8]) -> Vec<u8> {
    let n = script.len();
    let mut b = vec![];
    if n < 253 {
        b.push(n as u8);
    } else if n <= 65535 {
        b.push(253);
        b.extend_from_slice(&(n as u16).to_le_bytes());
    } else {
        b.push(254);
        b.extend_from_slice(&(n as u32).to_le_bytes());
    }
    b.extend_from_slice(script);
    b
}

struct Input {
    prevout: [u8; 36],
    sequence: u32,
    value: u64,
    script: Vec<u8>,
    pk: [u8; 33],
    path: Vec<u32>,
    signed: bool,
}
struct Spend {
    rk: [u8; 32],
    alpha: [u8; 32],
    value: u64,
    path: Vec<u32>,
    signed: bool,
}
struct Bundle {
    digest: [u8; 32],
    spends: Vec<Spend>,
}
struct Transaction {
    branch: u32,
    header: [u8; 32],
    inputs: Vec<Input>,
    outputs: Vec<u8>,
    output_count: usize,
    orchard: Bundle,
    ironwood: Bundle,
}

fn bundle(data: &[u8], ironwood: bool, v6: bool) -> Result<Bundle> {
    let personal = if ironwood {
        b"ZTxIdIronwd_H_v6"
    } else if v6 {
        b"ZTxIdOrchardH_v6"
    } else {
        b"ZTxIdOrchardHash"
    };
    let mut r = Reader::new(data);
    let n = r.count()?;
    if n == 0 {
        r.done()?;
        return Ok(Bundle {
            digest: hash(personal, &[]),
            spends: vec![],
        });
    }
    ensure!(!ironwood || v6, "Ironwood requires v6");
    let mut compact = vec![];
    let mut memos = vec![];
    let mut noncompact = vec![];
    let mut spends = vec![];
    for _ in 0..n {
        noncompact.extend_from_slice(&r.bytes::<32>()?); // cv_net
        compact.extend_from_slice(&r.bytes::<32>()?); // nullifier
        let rk = r.bytes()?;
        noncompact.extend_from_slice(&rk);
        r.bytes::<43>()?;
        let value = r.u64()?;
        r.bytes::<32>()?;
        r.bytes::<32>()?;
        let alpha = r.bytes()?;
        r.bytes::<32>()?;
        let path = r.path()?;
        compact.extend_from_slice(&r.bytes::<32>()?); // cmx
        compact.extend_from_slice(&r.bytes::<32>()?); // epk
        let enc = r.vector()?;
        ensure!(enc.len() == 580, "invalid encrypted note length");
        compact.extend_from_slice(&enc[..52]);
        memos.extend_from_slice(&enc[52..564]);
        noncompact.extend_from_slice(&enc[564..]);
        let out = r.vector()?;
        ensure!(out.len() == 80, "invalid outgoing ciphertext length");
        noncompact.extend_from_slice(&out);
        r.bytes::<43>()?;
        r.u64()?;
        r.bytes::<32>()?;
        r.bytes::<32>()?;
        if ironwood {
            ensure!(r.u8()? == 3, "invalid Ironwood note version");
        }
        spends.push(Spend {
            rk,
            alpha,
            value,
            path,
            signed: false,
        });
    }
    let flags = r.u8()?;
    ensure!(flags & !(if v6 { 7 } else { 3 }) == 0, "invalid flags");
    let magnitude = r.u64()?;
    let negative = r.u8()?;
    ensure!(negative <= 1, "invalid balance sign");
    let value = i64::try_from(magnitude)? * if negative == 1 { -1 } else { 1 };
    let anchor = r.bytes::<32>()?;
    r.done()?;
    let cp = if ironwood {
        b"ZTxIdIrnActCH_v6"
    } else {
        b"ZTxIdOrcActCHash"
    };
    let mp = if ironwood {
        b"ZTxIdIrnActMH_v6"
    } else {
        b"ZTxIdOrcActMHash"
    };
    let np = if ironwood {
        b"ZTxIdIrnActNH_v6"
    } else {
        b"ZTxIdOrcActNHash"
    };
    let c = hash(cp, &[&compact]);
    let m = hash(mp, &[&memos]);
    let nc = hash(np, &[&noncompact]);
    let f = [flags];
    let v = value.to_le_bytes();
    let mut parts: Vec<&[u8]> = vec![&c, &m, &nc, &f, &v];
    if !v6 {
        parts.push(&anchor);
    }
    Ok(Bundle {
        digest: hash(personal, &parts),
        spends,
    })
}

impl Transaction {
    fn parse(buffers: &[Vec<u8>; 5]) -> Result<Self> {
        let mut r = Reader::new(&buffers[0]);
        ensure!(r.bytes::<4>()? == *b"PCZT", "invalid PCZT magic");
        let pczt_version = r.u32()?;
        let version = r.u32()?;
        let group = r.u32()?;
        let branch = r.u32()?;
        ensure!(
            (version == 6 && group == 0xD884B698 && pczt_version == 2)
                || (version == 5 && group == 0x26A7270A && pczt_version == 1),
            "unsupported transaction version"
        );
        let lock = r.optional(0)?;
        let expiry = r.u32()?;
        let coin = r.u32()?;
        ensure!(coin == 133 || coin == 1, "invalid coin type");
        ensure!(r.u8()? == 0, "modifiable transactions unsupported");
        r.done()?;
        let header = hash(
            b"ZTxIdHeadersHash",
            &[
                &(version | HARDENED).to_le_bytes(),
                &group.to_le_bytes(),
                &branch.to_le_bytes(),
                &lock.to_le_bytes(),
                &expiry.to_le_bytes(),
            ],
        );
        let mut r = Reader::new(&buffers[1]);
        let n = r.count()?;
        let mut inputs = vec![];
        for _ in 0..n {
            let prevout = r.bytes()?;
            let sequence = r.optional(u32::MAX)?;
            let value = r.u64()?;
            let script = r.vector()?;
            ensure!(
                r.u8()? == 1 && r.count()? == 1,
                "only SIGHASH_ALL single-key inputs supported"
            );
            let pk = r.bytes()?;
            r.bytes::<32>()?;
            let path = r.path()?;
            ensure!(
                path.len() == 5
                    && path[0] == (44 | HARDENED)
                    && path[1] == (coin | HARDENED)
                    && path[2] & HARDENED != 0
                    && path[3] < HARDENED
                    && path[4] < HARDENED,
                "invalid BIP44 path"
            );
            // Limit transparent signing to the P2PKH form used by zkool.
            ensure!(
                script.len() == 25
                    && script[..3] == [0x76, 0xa9, 0x14]
                    && script[23..] == [0x88, 0xac],
                "only P2PKH supported"
            );
            let pubkey = PublicKey::from_slice(&pk)?;
            let TransparentAddress::PublicKeyHash(key_hash) =
                TransparentAddress::from_pubkey(&pubkey)
            else {
                unreachable!()
            };
            ensure!(
                script[3..23] == key_hash,
                "script does not match public key"
            );
            inputs.push(Input {
                prevout,
                sequence,
                value,
                script,
                pk,
                path,
                signed: false,
            });
        }
        r.done()?;
        let mut r = Reader::new(&buffers[2]);
        let output_count = r.count()?;
        let mut outputs = vec![];
        for _ in 0..output_count {
            outputs.extend_from_slice(&r.u64()?.to_le_bytes());
            outputs.extend_from_slice(&script_bytes(&r.vector()?));
            let n = r.count()?;
            ensure!(n <= 1, "unsupported output derivation");
            for _ in 0..n {
                r.bytes::<33>()?;
                r.bytes::<32>()?;
                r.path()?;
            }
        }
        r.done()?;
        let orchard = bundle(&buffers[3], false, version == 6)?;
        let ironwood = bundle(&buffers[4], true, version == 6)?;
        for s in orchard.spends.iter().chain(&ironwood.spends) {
            ensure!(
                s.path.len() == 3
                    && s.path[0] == (32 | HARDENED)
                    && s.path[1] == (coin | HARDENED)
                    && s.path[2] & HARDENED != 0,
                "invalid ZIP32 path"
            );
        }
        Ok(Self {
            branch,
            header,
            inputs,
            outputs,
            output_count,
            orchard,
            ironwood,
        })
    }
    fn digest(&self, input_index: Option<usize>, v6: bool) -> [u8; 32] {
        let mut prev = vec![];
        let mut seq = vec![];
        let mut amounts = vec![];
        let mut scripts = vec![];
        for i in &self.inputs {
            prev.extend_from_slice(&i.prevout);
            seq.extend_from_slice(&i.sequence.to_le_bytes());
            amounts.extend_from_slice(&i.value.to_le_bytes());
            scripts.extend_from_slice(&script_bytes(&i.script));
        }
        let p = hash(b"ZTxIdPrevoutHash", &[&prev]);
        let s = hash(b"ZTxIdSequencHash", &[&seq]);
        let o = hash(b"ZTxIdOutputsHash", &[&self.outputs]);
        let transparent = if self.inputs.is_empty() {
            if self.output_count == 0 {
                hash(b"ZTxIdTranspaHash", &[])
            } else {
                hash(b"ZTxIdTranspaHash", &[&p, &s, &o])
            }
        } else {
            let a = hash(b"ZTxTrAmountsHash", &[&amounts]);
            let sc = hash(b"ZTxTrScriptsHash", &[&scripts]);
            let txin = if let Some(index) = input_index {
                let i = &self.inputs[index];
                hash(
                    b"Zcash___TxInHash",
                    &[
                        &i.prevout,
                        &i.value.to_le_bytes(),
                        &script_bytes(&i.script),
                        &i.sequence.to_le_bytes(),
                    ],
                )
            } else {
                hash(b"Zcash___TxInHash", &[])
            };
            hash(b"ZTxIdTranspaHash", &[&[1], &p, &a, &sc, &s, &o, &txin])
        };
        let sapling = hash(b"ZTxIdSaplingHash", &[]);
        let mut personal = [0; 16];
        personal[..12].copy_from_slice(b"ZcashTxHash_");
        personal[12..].copy_from_slice(&self.branch.to_le_bytes());
        let mut parts: Vec<&[u8]> =
            vec![&self.header, &transparent, &sapling, &self.orchard.digest];
        if v6 {
            parts.push(&self.ironwood.digest);
        }
        hash(&personal, &parts)
    }
}

/// One device session. A new header replaces the previous transaction.
#[derive(Default)]
pub struct SigningSession {
    buffers: [Vec<u8>; 5],
    section: Option<usize>,
    transaction: Option<Transaction>,
    v6: bool,
}
impl SigningSession {
    pub fn execute(
        &mut self,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
        seed: &[u8],
    ) -> Result<Vec<u8>> {
        if matches!(ins, 0x55 | 0x57 | 0x59) {
            ensure!(p1 == 0 && data.is_empty(), "invalid signing request");
            let tx = self
                .transaction
                .as_mut()
                .ok_or_else(|| anyhow!("transaction not finalized"))?;
            let index = p2 as usize;
            ensure!(
                ins != 0x55 || index < tx.inputs.len(),
                "invalid input index"
            );
            let digest = tx.digest(if ins == 0x55 { Some(index) } else { None }, self.v6);
            if ins == 0x55 {
                let input = tx
                    .inputs
                    .get_mut(index)
                    .ok_or_else(|| anyhow!("invalid input index"))?;
                ensure!(!input.signed, "input already signed");
                let account = zip32::AccountId::try_from(input.path[2] & !HARDENED)
                    .map_err(|_| anyhow!("invalid account"))?;
                let key = if input.path[1] == (133 | HARDENED) {
                    AccountPrivKey::from_seed(
                        &zcash_protocol::consensus::MainNetwork,
                        seed,
                        account,
                    )
                } else {
                    AccountPrivKey::from_seed(
                        &zcash_protocol::consensus::TestNetwork,
                        seed,
                        account,
                    )
                }
                .map_err(|e| anyhow!("key derivation: {e}"))?;
                let key = key
                    .derive_secret_key(
                        TransparentKeyScope::custom(input.path[3]).unwrap(),
                        NonHardenedChildIndex::from_index(input.path[4]).unwrap(),
                    )
                    .map_err(|e| anyhow!("key derivation: {e}"))?;
                let secp = Secp256k1::new();
                ensure!(
                    PublicKey::from_secret_key(&secp, &key).serialize() == input.pk,
                    "public key does not match seed"
                );
                let mut result = secp
                    .sign_ecdsa(&Message::from_digest(digest), &key)
                    .serialize_der()
                    .to_vec();
                result.push(1);
                input.signed = true;
                return Ok(result);
            }
            let spend = if ins == 0x57 {
                tx.orchard.spends.get_mut(index)
            } else {
                tx.ironwood.spends.get_mut(index)
            }
            .ok_or_else(|| anyhow!("invalid action index"))?;
            ensure!(
                spend.value > 0 && !spend.signed,
                "dummy or already signed spend"
            );
            let account = zip32::AccountId::try_from(spend.path[2] & !HARDENED)
                .map_err(|_| anyhow!("invalid account"))?;
            let sk = SpendingKey::from_zip32_seed(seed, spend.path[1] & !HARDENED, account)
                .map_err(|e| anyhow!("key derivation: {e:?}"))?;
            let alpha = Option::<pallas::Scalar>::from(pallas::Scalar::from_repr(spend.alpha))
                .ok_or_else(|| anyhow!("invalid alpha"))?;
            let key = SpendAuthorizingKey::from(&sk).randomize(&alpha);
            let vk = orchard::primitives::redpallas::VerificationKey::from(&key);
            ensure!(
                <[u8; 32]>::from(vk) == spend.rk,
                "randomized key does not match seed"
            );
            let signature = key.sign(rand::rngs::OsRng, &digest);
            spend.signed = true;
            return Ok(<[u8; 64]>::from(&signature).to_vec());
        }
        let section = match ins {
            0x52 => 0,
            0x53 => 1,
            0x54 => 2,
            0x56 => 3,
            0x58 => 4,
            _ => bail!("unsupported instruction"),
        };
        ensure!(matches!(p1, 0 | 0x80 | 1) && p2 <= 1, "invalid framing");
        if section == 0 {
            ensure!(p1 == 0 && p2 == 0, "invalid header framing");
            *self = Self::default();
        }
        if p1 == 0 {
            ensure!(
                self.section
                    .map_or(section == 0, |previous| section == previous + 1),
                "unexpected section"
            );
            self.section = Some(section);
        } else {
            ensure!(self.section == Some(section), "unexpected continuation");
        }
        ensure!(self.transaction.is_none(), "transaction already finalized");
        ensure!(
            self.buffers[section].len() + data.len() <= MAX_BYTES,
            "transaction exceeds mock limit"
        );
        self.buffers[section].extend_from_slice(data);
        if p2 == 1 {
            ensure!(section == 4, "finish requires Ironwood section");
            let tx = Transaction::parse(&self.buffers)?;
            self.v6 = u32::from_le_bytes(self.buffers[0][8..12].try_into().unwrap()) == 6;
            self.transaction = Some(tx);
        }
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(version: u32) -> Vec<u8> {
        let mut h = b"PCZT".to_vec();
        for n in [
            if version == 6 { 2u32 } else { 1 },
            version,
            if version == 6 { 0xD884B698 } else { 0x26A7270A },
            0xc8e71055,
        ] {
            h.extend_from_slice(&n.to_le_bytes());
        }
        h.push(0);
        h.extend_from_slice(&500u32.to_le_bytes());
        h.extend_from_slice(&133u32.to_le_bytes());
        h.push(0);
        h
    }
    fn finalize(session: &mut SigningSession, input: &[u8], seed: &[u8]) {
        session.execute(0x52, 0, 0, &header(6), seed).unwrap();
        // Splitting any field across APDUs must preserve its digest.
        let split = input.len() / 2;
        session.execute(0x53, 0, 0, &input[..split], seed).unwrap();
        session.execute(0x53, 1, 0, &input[split..], seed).unwrap();
        session.execute(0x54, 0, 0, &[0], seed).unwrap();
        session.execute(0x56, 0, 0, &[0], seed).unwrap();
        session.execute(0x58, 0, 1, &[0], seed).unwrap();
    }
    #[test]
    fn transparent_signatures_verify_and_replays_are_rejected() {
        let seed = crate::handlers::seed(None);
        let account = AccountPrivKey::from_seed(
            &zcash_protocol::consensus::MainNetwork,
            &seed,
            zip32::AccountId::ZERO,
        )
        .unwrap();
        let secret = account
            .derive_external_secret_key(NonHardenedChildIndex::from_index(0).unwrap())
            .unwrap();
        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(&secp, &secret);
        let mut input = vec![1];
        input.extend_from_slice(&[2; 36]);
        input.push(0);
        input.extend_from_slice(&100000u64.to_le_bytes());
        let mut script = vec![0x76, 0xa9, 0x14];
        let TransparentAddress::PublicKeyHash(key_hash) = TransparentAddress::from_pubkey(&pk)
        else {
            unreachable!()
        };
        script.extend_from_slice(&key_hash);
        script.extend_from_slice(&[0x88, 0xac]);
        input.extend_from_slice(&script_bytes(&script));
        input.extend_from_slice(&[1, 1]);
        input.extend_from_slice(&pk.serialize());
        input.extend_from_slice(&[0; 32]);
        input.push(5);
        for n in [44 | HARDENED, 133 | HARDENED, HARDENED, 0, 0] {
            input.extend_from_slice(&n.to_be_bytes());
        }
        let mut s = SigningSession::default();
        finalize(&mut s, &input, &seed);
        let digest = s.transaction.as_ref().unwrap().digest(Some(0), true);
        assert!(s.execute(0x55, 0, 255, &[], &seed).is_err());
        let sig = s.execute(0x55, 0, 0, &[], &seed).unwrap();
        assert_eq!(*sig.last().unwrap(), 1);
        secp.verify_ecdsa(
            &Message::from_digest(digest),
            &secp256k1::ecdsa::Signature::from_der(&sig[..sig.len() - 1]).unwrap(),
            &pk,
        )
        .unwrap();
        assert!(s.execute(0x55, 0, 0, &[], &seed).is_err());
        finalize(&mut s, &input, &seed);
        assert!(s.execute(0x55, 0, 0, &[], &seed).is_ok());
    }
    #[test]
    fn rejects_incomplete_and_malformed_sessions() {
        let mut s = SigningSession::default();
        let seed = crate::handlers::seed(None);
        assert!(s.execute(0x59, 0, 0, &[], &seed).is_err());
        assert!(s.execute(0x53, 0, 0, &[0], &seed).is_err());
        s.execute(0x52, 0, 0, &header(6), &seed).unwrap();
        assert!(s.execute(0x58, 0, 1, &[0], &seed).is_err());
        assert!(Reader::new(&[253, 1, 0]).compact().is_err());
        assert!(bundle(&[1], true, true).is_err());
        assert!(bundle(&[0, 1], true, true).is_err());
    }
}
