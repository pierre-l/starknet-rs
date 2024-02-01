use starknet_crypto::pedersen_hash;
use starknet_ff::FieldElement;

use super::Event;

mod tree;

pub trait PedersenHash {
    fn pedersen_hash(&self) -> FieldElement;
}

impl PedersenHash for Event {
    /// Calculate the hash of an event.
    ///
    /// See the [documentation](https://docs.starknet.io/documentation/architecture_and_concepts/Smart_Contracts/starknet-events/#event_hash)
    /// for details.
    fn pedersen_hash(&self) -> FieldElement {
        let mut keys_hash = HashChain::default();
        for key in self.keys.iter() {
            keys_hash.update(*key);
        }
        let keys_hash = keys_hash.finalize();

        let mut data_hash = HashChain::default();
        for data in self.data.iter() {
            data_hash.update(*data);
        }
        let data_hash = data_hash.finalize();

        
        let mut event_hash = HashChain::default();
        event_hash.update(*&self.from_address);
        event_hash.update(keys_hash);
        event_hash.update(data_hash);

        event_hash.finalize()
    }
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
pub struct HashChain {
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

    pub fn chain_update(mut self, value: FieldElement) -> Self {
        self.update(value);
        self
    }

    pub fn finalize(self) -> FieldElement {
        let count = FieldElement::from_byte_slice_be(&self.count.to_be_bytes()).expect("usize is smaller than 251-bits");
        pedersen_hash(&self.hash, &count)
    }
}

#[cfg(test)]
mod tests {
    use super::{FieldElement, HashChain};

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
        let expected_hash = FieldElement::from_hex_be("0x66bd4335902683054d08a0572747ea78ebd9e531536fb43125424ca9f902084")
                .unwrap();

        assert_eq!(expected_hash, computed_hash);
    }
}
