use starknet_crypto::pedersen_hash;
use starknet_ff::FieldElement;

use crate::types::{DeclareTransaction, DeployAccountTransaction, InvokeTransaction};
use merkle_tree::calculate_root;

use super::{BlockWithTxs, Event, Transaction};

mod merkle_tree;

pub fn compute_block_hash(block: &BlockWithTxs, events: &[Event]) -> FieldElement {
    let transaction_commitment = calculate_transaction_commitment(&block.transactions);
    let event_commitment = calculate_event_commitment(&events);

    hash_array(&[
        from_u64(block.block_number),
        block.new_root,
        block.sequencer_address,
        from_u64(block.timestamp),
        from_usize(block.transactions.len()),
        transaction_commitment,
        from_usize(events.len()),
        event_commitment,
        FieldElement::ZERO,
        FieldElement::ZERO,
        block.parent_hash,
    ])
}

fn hash_array(felts: &[FieldElement]) -> FieldElement {
    let len_hash = &from_u128(felts.len() as u128);
    let cumulative_hash = felts
        .iter()
        .fold(FieldElement::default(), |current_hash, felt| {
            pedersen_hash(&current_hash, felt)
        });

    pedersen_hash(&cumulative_hash, len_hash)
}

fn from_u64(value: u64) -> FieldElement {
    from_u128(value as u128)
}

fn from_usize(value: usize) -> FieldElement {
    from_u128(value as u128)
}

// TODO Probably already implemented somewhere
fn from_u128(val: u128) -> FieldElement {
    let mut bytes = [0u8; 32];
    let val_bytes = val.to_be_bytes();
    let mut index = 16;
    while index < 32 {
        bytes[index] = val_bytes[index - 16];
        index += 1;
    }
    FieldElement::from_bytes_be(&bytes).unwrap()
}

/// Ported from [Pathfinder](https://github.com/eqlabs/pathfinder/blob/v0.10.3/crates/pathfinder/src/state/block_hash.rs#L319)
/// Calculate transaction commitment hash value.
///
/// The transaction commitment is the root of the Patricia Merkle tree with height 64
/// constructed by adding the (transaction_index, transaction_hash_with_signature)
/// key-value pairs to the tree and computing the root hash.
fn calculate_transaction_commitment(transactions: &[Transaction]) -> FieldElement {
    use rayon::prelude::*;

    let mut final_hashes = Vec::new();
    rayon::scope(|s| {
        s.spawn(|_| {
            final_hashes = transactions
                .par_iter()
                .map(|tx| calculate_transaction_hash_with_signature(tx))
                .collect();
        })
    });

    calculate_root(final_hashes)
}

fn calculate_transaction_hash_with_signature(tx: &Transaction) -> FieldElement {
    lazy_static::lazy_static!(
        static ref HASH_OF_EMPTY_LIST: FieldElement = HashChain::default().finalize();
    );

    let (tx_hash, signature_hash) = match tx {
        Transaction::Declare(t) => match t {
            DeclareTransaction::V0(t) => {
                (t.transaction_hash, calculate_signature_hash(&t.signature))
            }
            DeclareTransaction::V1(t) => {
                (t.transaction_hash, calculate_signature_hash(&t.signature))
            }
            DeclareTransaction::V2(t) => {
                (t.transaction_hash, calculate_signature_hash(&t.signature))
            }
            DeclareTransaction::V3(t) => {
                (t.transaction_hash, calculate_signature_hash(&t.signature))
            }
        },
        Transaction::DeployAccount(t) => match t {
            DeployAccountTransaction::V1(t) => {
                (t.transaction_hash, calculate_signature_hash(&t.signature))
            }
            DeployAccountTransaction::V3(t) => {
                (t.transaction_hash, calculate_signature_hash(&t.signature))
            }
        },
        Transaction::Invoke(t) => match t {
            InvokeTransaction::V0(t) => {
                (t.transaction_hash, calculate_signature_hash(&t.signature))
            }
            InvokeTransaction::V1(t) => {
                (t.transaction_hash, calculate_signature_hash(&t.signature))
            }
            InvokeTransaction::V3(t) => {
                (t.transaction_hash, calculate_signature_hash(&t.signature))
            }
        },
        Transaction::Deploy(t) => (t.transaction_hash, *HASH_OF_EMPTY_LIST),
        Transaction::L1Handler(t) => (t.transaction_hash, *HASH_OF_EMPTY_LIST),
    };

    pedersen_hash(&tx_hash, &signature_hash)
}

fn calculate_signature_hash(signature: &[FieldElement]) -> FieldElement {
    let mut hash = HashChain::default();
    for s in signature {
        hash.update(*s);
    }
    hash.finalize()
}

/// Ported from [Pathfinder](https://github.com/eqlabs/pathfinder/blob/v0.10.3/crates/pathfinder/src/state/block_hash.rs#L420)
/// Calculate event commitment hash value.
///
/// The event commitment is the root of the Patricia Merkle tree with height 64
/// constructed by adding the (event_index, event_hash) key-value pairs to the
/// tree and computing the root hash.
fn calculate_event_commitment(events: &[Event]) -> FieldElement {
    use rayon::prelude::*;

    let mut event_hashes = Vec::new();
    rayon::scope(|s| {
        s.spawn(|_| {
            event_hashes = events.par_iter().map(calculate_event_hash).collect();
        })
    });

    calculate_root(event_hashes)
}

/// Ported from [Pathfinder](https://github.com/eqlabs/pathfinder/blob/v0.10.3/crates/pathfinder/src/state/block_hash.rs#L454)
/// Calculate the hash of an event.
///
/// See the [documentation](https://docs.starknet.io/documentation/architecture_and_concepts/Smart_Contracts/starknet-events/#event_hash)
/// for details.
fn calculate_event_hash(event: &Event) -> FieldElement {
    let mut keys_hash = HashChain::default();
    for key in event.keys.iter() {
        keys_hash.update(*key);
    }
    let keys_hash = keys_hash.finalize();

    let mut data_hash = HashChain::default();
    for data in event.data.iter() {
        data_hash.update(*data);
    }
    let data_hash = data_hash.finalize();

    let mut event_hash = HashChain::default();
    event_hash.update(event.from_address);
    event_hash.update(keys_hash);
    event_hash.update(data_hash);

    event_hash.finalize()
}

/// Ported from [Pathfinder](https://github.com/eqlabs/pathfinder/blob/v0.10.3/crates/crypto/src/hash/pedersen/chain.rs)
/// HashChain is the structure used over at cairo side to represent the hash construction needed
/// for computing the class hash.
///
/// Empty hash chained value equals `H(0, 0)` where `H` is the [`pedersen_hash()`] function, and the
/// second value is the number of values hashed together in this chain. For other values, the
/// accumulator is on each update replaced with the `H(hash, value)` and the number of count
/// incremented by one.
#[derive(Default)]
struct HashChain {
    hash: FieldElement,
    count: usize,
}

impl HashChain {
    pub fn update(&mut self, value: FieldElement) {
        self.hash = pedersen_hash(&self.hash, &value);
        self.count = self
            .count
            .checked_add(1)
            .expect("could not have deserialized larger than usize Vecs");
    }

    pub fn finalize(self) -> FieldElement {
        let count = FieldElement::from_byte_slice_be(&self.count.to_be_bytes())
            .expect("usize is smaller than 251-bits");
        pedersen_hash(&self.hash, &count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_empty_chain() {
        let mut chain = HashChain::default();

        chain.update(FieldElement::from_hex_be("0x1").unwrap());
        chain.update(FieldElement::from_hex_be("0x2").unwrap());
        chain.update(FieldElement::from_hex_be("0x3").unwrap());
        chain.update(FieldElement::from_hex_be("0x4").unwrap());

        let computed_hash = chain.finalize();

        // produced by the cairo-lang Python implementation:
        // `hex(compute_hash_on_elements([1, 2, 3, 4]))`
        let expected_hash = FieldElement::from_hex_be(
            "0x66bd4335902683054d08a0572747ea78ebd9e531536fb43125424ca9f902084",
        )
        .unwrap();

        assert_eq!(expected_hash, computed_hash);
    }
}
