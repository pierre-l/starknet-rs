use starknet_crypto::pedersen_hash;
use starknet_ff::FieldElement;
// TODO Replace with a proper error.
use anyhow::Result;

use crate::types::{DeclareTransaction, DeployAccountTransaction, InvokeTransaction};
use tree::calculate_root;

use super::{BlockWithTxs, EmittedEvent, Event, Transaction};

mod tree;

// TODO Pretty much useless. Get rid of this trait.
pub trait PedersenHash {
    fn pedersen_hash(&self) -> Result<FieldElement>;
}

pub fn compute_block_hash(block: &BlockWithTxs, events: &[Event]) -> Result<FieldElement> {
    /* TODO
    h(𝐵) = h(
        block_number,
        global_state_root,
        sequencer_address,
        block_timestamp,
        transaction_count,
        transaction_commitment,
        event_count,
        event_commitment,
        0,
        0,
        parent_block_hash
    )
    */
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

    // TODO Inefficient, find a better way. Pathfinder's Felt::from.
    fn from_u64(value: u64) -> FieldElement {
        // TODO FieldElement::from_dec_str(&value.to_string()).unwrap()
        from_u128(value as u128)
    }

    let transaction_commitment =
        calculate_transaction_commitment(&block.transactions)?;
    let event_commitment = calculate_event_commitment(&events)?;

    Ok(hash_felts(&[
        dbg!(from_u64(block.block_number)),
        block.new_root,
        block.sequencer_address,
        from_u64(block.timestamp),
        dbg!(from_u64(dbg!(block.transactions.len() as u64))),
        transaction_commitment,
        from_u64(events.len() as u64),
        event_commitment, 
        FieldElement::ZERO,
        FieldElement::ZERO,
        block.parent_hash
    ]))
}

/*
TODO Crude, refactor
 */
pub fn hash_felts(felts: &[FieldElement]) -> FieldElement {
    felts
        .iter()
        .fold(FieldElement::default(), |current_hash, felt| {
            pedersen_hash(&current_hash, felt)
        })
}

impl PedersenHash for Event {
    /// Calculate the hash of an event.
    ///
    /// See the [documentation](https://docs.starknet.io/documentation/architecture_and_concepts/Smart_Contracts/starknet-events/#event_hash)
    /// for details.
    fn pedersen_hash(&self) -> Result<FieldElement> {
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

        Ok(event_hash.finalize())
    }
}

/// Ported from [Pathfinder](https://github.com/eqlabs/pathfinder/blob/v0.10.3/crates/pathfinder/src/state/block_hash.rs#L319)
/// Calculate transaction commitment hash value.
///
/// The transaction commitment is the root of the Patricia Merkle tree with height 64
/// constructed by adding the (transaction_index, transaction_hash_with_signature)
/// key-value pairs to the tree and computing the root hash.
pub fn calculate_transaction_commitment(
    transactions: &[Transaction],
) -> Result<FieldElement> {
    use rayon::prelude::*;

    // TODO Directly poll the tx hashes?
    let mut final_hashes = Vec::new();
    rayon::scope(|s| {
        s.spawn(|_| {
            final_hashes = transactions
                .par_iter()
                .map(|tx| calculate_transaction_hash_with_signature(tx))
                .collect();
        })
    });

    Ok(calculate_root(final_hashes))
}

fn calculate_transaction_hash_with_signature(tx: &Transaction) -> FieldElement {
    lazy_static::lazy_static!(
        static ref HASH_OF_EMPTY_LIST: FieldElement = HashChain::default().finalize();
    );

    let (tx_hash, signature_hash) = match tx {
        Transaction::Declare(t) => match t {
            DeclareTransaction::V0(t) => (t.transaction_hash, calculate_signature_hash(&t.signature)),
            DeclareTransaction::V1(t) => (t.transaction_hash, calculate_signature_hash(&t.signature)),
            DeclareTransaction::V2(t) => (t.transaction_hash, calculate_signature_hash(&t.signature)),
            DeclareTransaction::V3(t) => (t.transaction_hash, calculate_signature_hash(&t.signature)),
        },
        Transaction::DeployAccount(t) => match t {
            DeployAccountTransaction::V1(t) => (t.transaction_hash, calculate_signature_hash(&t.signature)),
            DeployAccountTransaction::V3(t) => (t.transaction_hash, calculate_signature_hash(&t.signature)),
        },
        Transaction::Invoke(t) => match t {
            InvokeTransaction::V0(t) => (t.transaction_hash, calculate_signature_hash(&t.signature)),
            InvokeTransaction::V1(t) => (t.transaction_hash, calculate_signature_hash(&t.signature)),
            InvokeTransaction::V3(t) => (t.transaction_hash, calculate_signature_hash(&t.signature)),
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
pub fn calculate_event_commitment(events: &[Event]) -> Result<FieldElement> {
    use rayon::prelude::*;

    let mut event_hashes = Vec::new();
    rayon::scope(|s| {
        s.spawn(|_| {
            event_hashes = events
                .par_iter()
                .map(calculate_event_hash)
                .collect();
        })
    });

    Ok(calculate_root(event_hashes))
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
    use crate::types::EventsPage;

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
        let expected_hash = FieldElement::from_hex_be("0x66bd4335902683054d08a0572747ea78ebd9e531536fb43125424ca9f902084")
                .unwrap();

        assert_eq!(expected_hash, computed_hash);
    }

    #[test]
    fn block_hash_computation() {
        // TODO
        let expected = FieldElement::from_hex_be("0x780cea3e1af61f818a184db7a8ebed6fd48949d35ff51e46a0c09257f84160c").unwrap();

        let block: BlockWithTxs = serde_json::from_str(BLOCK).unwrap();
        let events_page: EventsPage = serde_json::from_str(EVENTS_PAGE).unwrap();
        let events = events_page.events.into_iter().map(|e| Event {
            from_address: e.from_address,
            keys: e.keys,
            data: e.data,
        }).collect::<Vec<Event>>();

        assert_eq!(compute_block_hash(&block, &events).unwrap(), expected);
    }

    static BLOCK: &str = r#"{"status":"ACCEPTED_ON_L1","block_hash":"0x780cea3e1af61f818a184db7a8ebed6fd48949d35ff51e46a0c09257f84160c","parent_hash":"0x59a48af46243101bfcbf219b90798738e8490070a2e836b8e0338f2743b5b75","block_number":942701,"new_root":"0xd94e5a9febc1d51817e562581d5623992531b20e14d8a2336f9b2b65ec3909","timestamp":1706753043,"sequencer_address":"0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8","transactions":[{"transaction_hash":"0x661476527e056e48c280410c3bd2ec014da16cc8cf8c84961205c8896aa1799","type":"INVOKE","sender_address":"0x1d8e01188c4c8984fb19f00156491787e64fd2de1c3ce4eb9571924c540cf3b","calldata":["0x1","0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167","0x3d0bcca55c118f88a08e0fcc06f43906c0c174feb52ebc83f0fa28a1f59ed67","0x0","0x63","0x63","0xe","0x0","0x65bafc10","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x3d2bdffb26a","0x4254432f555344","0x2285844799992c4770200","0x0","0x65bafc10","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x5f40ac8","0x574254432f425443","0x46f7ff6dc39000","0x0","0x65bafc10","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x3d19063ae60","0x574254432f555344","0x2d8578a36abc44c000","0x0","0x65bafc10","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x3890fdc51e0","0x4254432f455552","0xfb8de9ed8e321122000","0x0","0x65bafc10","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x3455422e60","0x4554482f555344","0xae3421e84e434e8d0000","0x0","0x65bafc10","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x231b6d400","0x534f4c2f555344","0xd33ff5f2bf5654440000","0x0","0x65bafc10","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x5ee606d","0x4441492f555344","0x1a898ce178794b15500","0x0","0x65bafc10","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x23532140","0x554e492f555344","0x614436fdefe93bc000","0x0","0x65bafc10","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0xf4047","0x555344542f555344","0xb90121e62630e6b40","0x0","0x65bafc10","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0xf422e","0x555344432f555344","0xe9c3d583ab783180","0x0","0x65bafc10","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x4955596","0x4d415449432f555344","0xac8c72d6533190b3000","0x0","0x65bafc10","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x85e93595","0x4554482f55534443","0x3b2619423159a897280","0x0","0x65bafc10","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0xf3546","0x4441492f55534443","0x57e799065d6a680","0x0","0x65bafc10","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x9ee27ee60","0x574254432f55534443","0x0"],"max_fee":"0xde0b6b3a7640000","version":"0x1","signature":["0x4e36eff9e88ee561f9cbb307980ecf847ff8c47b6f165adaa4316d39e645cbf","0x18671e5ea6c26c5fc249aeedd1d7b63158a0a6139eb773cd9bf79c1443bf7da"],"nonce":"0x52ce9"},{"transaction_hash":"0x563ac15c24ddad96b4e36cb7fbcb521c2c6c6d9741028deb6eb1af060e264aa","type":"INVOKE","sender_address":"0x264cd871a4b5a6b441eb2862b3785e01c4cb82a133e3a65a01827bb8df4b871","calldata":["0x1","0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167","0x3d0bcca55c118f88a08e0fcc06f43906c0c174feb52ebc83f0fa28a1f59ed67","0x39","0x8","0x0","0x65bafc16","0x464c4f574445534b","0x464c4f574445534b","0x3d1d9e6c7d2","0x4254432f555344","0x0","0x0","0x65bafc16","0x464c4f574445534b","0x464c4f574445534b","0x344cdeb2c5","0x4554482f555344","0x0","0x0","0x65bafc16","0x464c4f574445534b","0x464c4f574445534b","0x3cfff703fdd","0x574254432f555344","0x0","0x0","0x65bafc16","0x464c4f574445534b","0x464c4f574445534b","0x5f31daa","0x574254432f425443","0x0","0x0","0x65bafc16","0x464c4f574445534b","0x464c4f574445534b","0x388ccd3db54","0x4254432f455552","0x0","0x0","0x65bafc16","0x464c4f574445534b","0x464c4f574445534b","0xf3f31","0x555344542f555344","0x0","0x0","0x65bafc16","0x464c4f574445534b","0x464c4f574445534b","0x5f61b98","0x555344432f555344","0x0","0x0","0x65bafc16","0x464c4f574445534b","0x464c4f574445534b","0xf413f","0x4441492f555344","0x0"],"max_fee":"0x16345785d8a0000","version":"0x1","signature":["0x3642662e9b345dd81ee9402196b6b99fe2412e18c45d75e03cab07045c0adbc","0xa87d31341e3a464a8288fb3286d8de364ce8f5ad44df5d05c9754be62ccf8f"],"nonce":"0x1317b"},{"transaction_hash":"0x1d9a9d7e808c6e79a168a61939f630896bc26d4666408aec61b9857b5a91272","type":"INVOKE","sender_address":"0x342dacf32f4c403a400c9b2a9e9f36c5dcdf88223da58393d660bfd2020d248","calldata":["0x1","0x71d07b1217cdcc334739a3f28da75db05d62672ad04b9204ee11b88f2f9f61c","0xf2f7c15cbe06c8d94597cd91fd7f3369eae842359235712def5584f8d270cd","0xa","0x13c3","0x1","0x0","0x0","0x0","0x0","0x0","0x1","0x0","0x0"],"max_fee":"0x7179d714add","version":"0x1","signature":["0x42116310b8ec9c9a3d47a86602f648855c1d13596d4dcc36bdc668290ee5e75","0x774ad0407f54b64cd7f9a03e8139f9b52053510727b03bc19f744ca1a0a4fe5"],"nonce":"0x4ff"},{"transaction_hash":"0x16999fef9d6ebe36041d5f2e0b15976dea33d3c1c00438e2bd722136f978dce","type":"INVOKE","sender_address":"0x264cd871a4b5a6b441eb2862b3785e01c4cb82a133e3a65a01827bb8df4b871","calldata":["0x1","0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167","0x3d0bcca55c118f88a08e0fcc06f43906c0c174feb52ebc83f0fa28a1f59ed67","0x21","0x4","0x1","0x65bafc16","0x464c4f574445534b","0x464c4f574445534b","0x3d19a97a55f","0x4254432f555344","0x0","0x0","0x1","0x65bafc16","0x464c4f574445534b","0x464c4f574445534b","0x34494e6075","0x4554482f555344","0x0","0x0","0x1","0x65bafc16","0x464c4f574445534b","0x464c4f574445534b","0x9c85884b0","0x4254432f55534454","0x0","0x0","0x1","0x65bafc16","0x464c4f574445534b","0x464c4f574445534b","0x85eee168","0x4554482f55534454","0x0","0x0"],"max_fee":"0x16345785d8a0000","version":"0x1","signature":["0x908b91ae1be43e23bb00d152c420f0cdbd874991e34ad0d7e05a3dcf83ee11","0x2088345aa4048a6d76bdb3820b64f38d50a7b32461a02c550dd10ef186c9ec6"],"nonce":"0x1317c"},{"transaction_hash":"0x7707d55127f449ad2ec58e79d5db3a1d5d5f10e538100d82ece602dca2efc21","type":"INVOKE","sender_address":"0x6948fee1708433a6c35cbaaa14048ceaf9616dc0f4004096b9b3a3931456c13","calldata":["0x1","0x5e367ac160e5f90c5775089b582dfc987dd148a5a2f977c49def2a6644f724b","0x2f0b3c5710379609eb5495f1ecd348cb28167711b73609fe565a72734550354","0x0","0x3","0x3","0x6948fee1708433a6c35cbaaa14048ceaf9616dc0f4004096b9b3a3931456c13","0x21e19e0c9bab240000","0x0"],"max_fee":"0xcbba106e000","version":"0x1","signature":["0x1","0xa34db978110168f7c4b1383874494a34","0xdd6da99a082d2fb66fd3c10b17c9b1cd","0xa1837db1f4ee20bd78c5595b9167f3c2","0xcb87642765e9498ee4c2f15d72da4ae"],"nonce":"0x13"},{"transaction_hash":"0x55997be389780c4bdcdc35c826abb1f03209d3db778ea88c7cf36f5b9d51200","type":"INVOKE","sender_address":"0x4b37cc6fda08bcedd4c0e77b8343bb0c1d4302e6795b57addd8ffe42ab65b13","calldata":["0x1","0x71d07b1217cdcc334739a3f28da75db05d62672ad04b9204ee11b88f2f9f61c","0x2d1af4265f4530c75b41282ed3b71617d3d435e96fe13b08848482173692f4f","0x2","0x13bf","0x1"],"max_fee":"0x110d9316ec000","version":"0x1","signature":["0x1797ff637b3272fa294891cfcad0b9cf5db91b341fdead279a09867a11d4f4f","0x3f55e563216b0fc069835ddf3a3ed25715025c79759260c94787fcdc094582e"],"nonce":"0x7"},{"transaction_hash":"0x6d51686bf4b833497cac1915b43ca81518d93dc3726956f3d5d1223aa212a04","type":"INVOKE","sender_address":"0x23010788ae442014c87605e0ce4ce787eb15489176f8e286f8e3b06f6d68d9","calldata":["0x1","0x71d07b1217cdcc334739a3f28da75db05d62672ad04b9204ee11b88f2f9f61c","0x2d1af4265f4530c75b41282ed3b71617d3d435e96fe13b08848482173692f4f","0x2","0x101d","0x1"],"max_fee":"0x110d9316ec000","version":"0x1","signature":["0x3d9f98dc7621f531993b015e099a5ddbd53608fe0db5ce17c2f5f686968e01a","0xce96c52acf932878bfe7860615ff7dc3d63fb06798b94ba93d961920e21b7e"],"nonce":"0x4"},{"transaction_hash":"0x1826182847672d6c877fb4cb0015a8824978f2a5d48808e0d7191b7c2480f15","type":"INVOKE","sender_address":"0x1d8e01188c4c8984fb19f00156491787e64fd2de1c3ce4eb9571924c540cf3b","calldata":["0x1","0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167","0x3d0bcca55c118f88a08e0fcc06f43906c0c174feb52ebc83f0fa28a1f59ed67","0x0","0x63","0x63","0xe","0x0","0x65bafc2d","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x3d2567c4440","0x4254432f555344","0x2281dd9bf6b7e995b4000","0x0","0x65bafc2d","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x5f4a9b6","0x574254432f425443","0x46ff6604adec00","0x0","0x65bafc2d","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x3d18ee63620","0x574254432f555344","0x2d8566dff184644000","0x0","0x65bafc2d","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x38891c6e50a","0x4254432f455552","0xfb6adeb07b4b3f7b600","0x0","0x65bafc2d","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x3452de0ca5","0x4554482f555344","0xae1b1e0b2c58b4469200","0x0","0x65bafc2d","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x2313295d5","0x534f4c2f555344","0xd30e3a0cbfa1650ab100","0x0","0x65bafc2d","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x5ee606d","0x4441492f555344","0x1a89b6dc9e719f08c00","0x0","0x65bafc2d","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x2340d41e","0x554e492f555344","0x610ce5bf4858fe6600","0x0","0x65bafc2d","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0xf4047","0x555344542f555344","0xb902c776d52b9ac40","0x0","0x65bafc2d","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0xf422e","0x555344432f555344","0xe9c3d583ab783180","0x0","0x65bafc2d","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x4948541","0x4d415449432f555344","0xac72b272e0188c54500","0x0","0x65bafc2d","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x85e39045","0x4554482f55534443","0x3b239adc3cc6e6c4a80","0x0","0x65bafc2d","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0xf3546","0x4441492f55534443","0x57e799065d6a680","0x0","0x65bafc2d","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x9ee27ee60","0x574254432f55534443","0x0"],"max_fee":"0xde0b6b3a7640000","version":"0x1","signature":["0x2d44bf923731b0cd0345e7ff03643b2694dd667ac81116e70f639edda8bb341","0x97a18ad0b02dfe0c4b39293b93fa6585ca173a19ce226d739784ee7d9a7861"],"nonce":"0x52cea"},{"transaction_hash":"0xece6d4f372169de7b08550578289f99c8547dba5985e260b66ca6e125deebf","type":"INVOKE","sender_address":"0x35acd6dd6c5045d18ca6d0192af46b335a5402c02d41f46e4e77ea2c951d9a3","calldata":["0x2","0x6359ed638df79b82f2f9dbf92abbcb41b57f9dd91ead86b1c85d2dee192c","0xf818e4530ec36b83dfe702489b4df537308c3b798b0cc120e32c2056d68b7d","0x0","0x6359ed638df79b82f2f9dbf92abbcb41b57f9dd91ead86b1c85d2dee192c","0x2468d193cd15b621b24c2a602b8dbcfa5eaa14f88416c40c09d7fd12592cb4b","0x0"],"max_fee":"0x22b1c8c1227a00000","version":"0x1","signature":["0x756bde609d5e161dc8e711ba20eb519db09436f090c0352d9649aa2c39c362d","0x3a59a8a181b2e19d8a3325427a0022fcea22c2bfb27fcf7d5250f8c7612b9c6"],"nonce":"0x10fad"},{"transaction_hash":"0x43973e9395b8d9952e4b3de76a2b66203d5cdcadd32e55a03cf9c42c5dfa098","type":"INVOKE","sender_address":"0x342dacf32f4c403a400c9b2a9e9f36c5dcdf88223da58393d660bfd2020d248","calldata":["0x1","0x71d07b1217cdcc334739a3f28da75db05d62672ad04b9204ee11b88f2f9f61c","0x1f64d317ff277789ba74de95db50418ab0fa47c09241400b7379b50d6334c3a","0x2","0x13c3","0x1"],"max_fee":"0x7778a35dd3c","version":"0x1","signature":["0x66f108df1adb8a7d29b4d1526da156b6da8c952859c709b22df97ab6351a115","0x300a762c6b7028bfa3f1d7cf223930b8d3b2eb99c6567496affe755fed35d33"],"nonce":"0x500"},{"transaction_hash":"0x65e195f97cf3ee81ac7ea7c156c94456f210d708efff0ac949740a4c63a8e07","type":"INVOKE","sender_address":"0x6948fee1708433a6c35cbaaa14048ceaf9616dc0f4004096b9b3a3931456c13","calldata":["0x2","0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7","0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e","0x0","0x3","0x5e367ac160e5f90c5775089b582dfc987dd148a5a2f977c49def2a6644f724b","0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e","0x3","0x3","0x6","0x1f0be1f650e2e8a25f31fb1feb3c4d667b5352676edf00aa7c3a8ac4cf7eb52","0x38d7ea4c68000","0x0","0x1f0be1f650e2e8a25f31fb1feb3c4d667b5352676edf00aa7c3a8ac4cf7eb52","0x15af1d78b58c40000","0x0"],"max_fee":"0xe8d4a510000","version":"0x1","signature":["0x1","0x5f882cdc099ce28c642c424ab587354d","0x5dbdf04d39aec2845e76f4ff95c7d958","0x3a17fc31af56d75d5ed76f57c41f91db","0x6fb465e678f3ba5c30a152075784a686"],"nonce":"0x14"},{"transaction_hash":"0x4e2f729cc7a7fd0258e2633d2b77bd300c76bd5fbd4683aa1694904e2692fa0","type":"DEPLOY_ACCOUNT","max_fee":"0x1402462f6000","version":"0x1","signature":["0x1369e89708c07753b5767cf4ecbc903ca5ffebe74f3a33beeb826d220b6ca2a","0x164ce94414d37d6e47a1536febf6d1a2454c91acceb2c9435af4e45510d61b8","0x5dec330eebf36c8672b60db4a718d44762d3ae6d1333e553197acb47ee5a062","0x0","0x0","0x0","0x0","0x0","0x0","0x0"],"nonce":"0x0","contract_address_salt":"0x5b7e71fa8f5c0db720ced0d5dad880dd862b5918ccf038f07a8c4afd82774cc","constructor_calldata":["0x5aa23d5bb71ddaa783da7ea79d405315bafa7cf0387a74f4593578c3e9e6570","0x2dd76e7ad84dbed81c314ffe5e7a7cacfb8f4836f01af4e913f275f89a3de1a","0x1","0x5b7e71fa8f5c0db720ced0d5dad880dd862b5918ccf038f07a8c4afd82774cc"],"class_hash":"0x3131fa018d520a037686ce3efddeab8f28895662f019ca3ca18a626650f7d1e"},{"transaction_hash":"0x6e833cddbeec33c828f2c0f1d959d45b0320bf62c36a746ddc12ca7abf7d0f1","type":"INVOKE","sender_address":"0x574bd20a5f65a466b37d8f49f0116f9f2d2cee29248837a09a7e3407a0fa298","calldata":["0x1","0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d","0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e","0x0","0x3","0x3","0x186067bedd8e59a39187212ba14414efc784f9b00c8e06fd6b369c86f5e0c53","0x71afd498d0000","0x0"],"max_fee":"0x3fc74215b5e6","version":"0x1","signature":["0xdd4987e2180cabc601e91910bc331cf1b85c4a1b9f11ad2b58fd02cae818c9","0x21bdffc317c5a4713e528b1c64b764fa0df6d379ca8c9f0c2c46656f851c46b"],"nonce":"0x2a8a6"},{"transaction_hash":"0x3cd0c7bb43b2b07a51741f9dd5bd954e756aafc25107d29cd5a0d87b93c06ed","type":"INVOKE","sender_address":"0x1d8e01188c4c8984fb19f00156491787e64fd2de1c3ce4eb9571924c540cf3b","calldata":["0x1","0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167","0x3d0bcca55c118f88a08e0fcc06f43906c0c174feb52ebc83f0fa28a1f59ed67","0x0","0x63","0x63","0xe","0x0","0x65bafc4b","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x3d1b2c05f80","0x4254432f555344","0x228778f280ec4af0d8000","0x0","0x65bafc4b","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x5f5a90b","0x574254432f425443","0x470b49d0335600","0x0","0x65bafc4b","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x3d18ee63620","0x574254432f555344","0x2d8566dff184644000","0x0","0x65bafc4b","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x38869d4f680","0x4254432f455552","0xfb5fc47a4cb47b98000","0x0","0x65bafc4b","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x344b9734a0","0x4554482f555344","0xae0b6d66ea5a35b6a000","0x0","0x65bafc4b","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x2305cf655","0x534f4c2f555344","0xd2def69f3211158d0e00","0x0","0x65bafc4b","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x5ee61ba","0x4441492f555344","0x1a89bcae91e7e359800","0x0","0x65bafc4b","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x23425a8b","0x554e492f555344","0x611a2057b2e9761800","0x0","0x65bafc4b","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0xf4047","0x555344542f555344","0xb901fd5143da4e5c0","0x0","0x65bafc4b","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0xf422e","0x555344432f555344","0xe9c201220bf1fb00","0x0","0x65bafc4b","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x4931f2b","0x4d415449432f555344","0xac5ab0b99fcae659200","0x0","0x65bafc4b","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x85d9a535","0x4554482f55534443","0x3b200cc4efdc6cfc480","0x0","0x65bafc4b","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0xf3546","0x4441492f55534443","0x57e64b715294000","0x0","0x65bafc4b","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x9ee27ee60","0x574254432f55534443","0x0"],"max_fee":"0xde0b6b3a7640000","version":"0x1","signature":["0x13be3d59bfa3b9bb764d3d72a523e35825c978a80a25fa5963522bfd1c942ea","0x352a627907cd9bb550e227b3d486b5dfad6ce8a1f60e7d5e41dc1f8d1ada3ee"],"nonce":"0x52ceb"},{"transaction_hash":"0x2a96d2e2738067d4561d7ecdf86aac9c4eb9f5ba123f8d8f1ef1481a02d1965","type":"INVOKE","sender_address":"0x4afc1995e0606c2371bbd336e13eec14a3066234025f01d56f067717ce7a910","calldata":["0x1","0x5e367ac160e5f90c5775089b582dfc987dd148a5a2f977c49def2a6644f724b","0x2f0b3c5710379609eb5495f1ecd348cb28167711b73609fe565a72734550354","0x0","0x3","0x3","0x4afc1995e0606c2371bbd336e13eec14a3066234025f01d56f067717ce7a910","0x21e19e0c9bab240000","0x0"],"max_fee":"0x1402462f6000","version":"0x1","signature":["0x63286c9d42323858047cd30b28089b714d71e8f6ecd57568e996a0b5a7d1997","0x723be7e3468176c59d4ba6a598ae45f0573b9f3d20653db87bc9abb2ffbf29a"],"nonce":"0x1"},{"transaction_hash":"0x2fe028a3795d099f73ce78a11a2955c708638abb2cf04f504f85622311ff0ef","type":"DEPLOY_ACCOUNT","max_fee":"0x121b31f0e51c","version":"0x1","signature":["0x6ff63a22c381bea88171a6b2bd25f2023fac287c724d227dee9e031a519e91","0x298a79243f9b74a21eba838b448f696904b6a87ee52f82fdff2d64d6f1c1bfa"],"nonce":"0x0","contract_address_salt":"0x4d13a31941a1b9849a8f81bea38b6add5c65998c2291bdc88dfd9721e59e030","constructor_calldata":["0x4d13a31941a1b9849a8f81bea38b6add5c65998c2291bdc88dfd9721e59e030","0x6948fee1708433a6c35cbaaa14048ceaf9616dc0f4004096b9b3a3931456c13"],"class_hash":"0x715b5e10bf63c36e69c402a81e1eb96b9107ef56eb5e821b00893e39bdcf545"},{"transaction_hash":"0x6e5ecf7a19af0356f919ec8a68d61febe4f24a2b1a2c97128f3167c7ed8c28c","type":"INVOKE","sender_address":"0x6948fee1708433a6c35cbaaa14048ceaf9616dc0f4004096b9b3a3931456c13","calldata":["0x2","0x1f0be1f650e2e8a25f31fb1feb3c4d667b5352676edf00aa7c3a8ac4cf7eb52","0x335f4be7a6745c95f27d2222d0349d426ebfe66d2d40874abb0b47cce9c783f","0x0","0x3","0x1f0be1f650e2e8a25f31fb1feb3c4d667b5352676edf00aa7c3a8ac4cf7eb52","0x22b342738693c44dc4cdfba2e13456232c8528a2ec23b2222be17bd91a9addb","0x3","0xd","0x10","0x1","0x71d07b1217cdcc334739a3f28da75db05d62672ad04b9204ee11b88f2f9f61c","0x1","0x4","0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7","0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e","0x1","0x5e367ac160e5f90c5775089b582dfc987dd148a5a2f977c49def2a6644f724b","0x219209e083275171774dab1df80982e9df2096516f06319c5c6d71ae0a8480c","0x1","0x5e367ac160e5f90c5775089b582dfc987dd148a5a2f977c49def2a6644f724b","0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e","0x1","0x5e367ac160e5f90c5775089b582dfc987dd148a5a2f977c49def2a6644f724b","0x2f0b3c5710379609eb5495f1ecd348cb28167711b73609fe565a72734550354","0x1"],"max_fee":"0x1147c8403000","version":"0x1","signature":["0x1","0xb10689181979acc65edea59d8e0a984f","0x28c2b380c371a68118c1731b0c1ae9a8","0xfe394dbc304fb1c4c6ed1faa640f475d","0xd28841b4eb894d9367536184f710e19c"],"nonce":"0x15"},{"transaction_hash":"0x3dc1a551432d476617a83188b83ba2eed93280f5141f00cf0017a1607ed9da5","type":"INVOKE","sender_address":"0x1d8e01188c4c8984fb19f00156491787e64fd2de1c3ce4eb9571924c540cf3b","calldata":["0x1","0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167","0x3d0bcca55c118f88a08e0fcc06f43906c0c174feb52ebc83f0fa28a1f59ed67","0x0","0x63","0x63","0xe","0x0","0x65bafc67","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x3d1afac0095","0x4254432f555344","0x228e7a2fe0f040f0cd200","0x0","0x65bafc67","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x5f48037","0x574254432f425443","0x46fd7758a6ae00","0x0","0x65bafc67","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x3d0cda19680","0x574254432f555344","0x2d7c66f0a11b8d0000","0x0","0x65bafc67","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x38840b6f10a","0x4254432f455552","0xfb5456dbd55266bb600","0x0","0x65bafc67","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x344a606f55","0x4554482f555344","0xadd578693e4740036800","0x0","0x65bafc67","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x230620c6a","0x534f4c2f555344","0xd2e0854726f94ca67600","0x0","0x65bafc67","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x5ee61ba","0x4441492f555344","0x1a82645dd79bc0e0a00","0x0","0x65bafc67","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x23425a8b","0x554e492f555344","0x6110466892ae301400","0x0","0x65bafc67","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0xf4047","0x555344542f555344","0xb90ccb0ec347c5bc0","0x0","0x65bafc67","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0xf422e","0x555344432f555344","0xe9c1d0056b102600","0x0","0x65bafc67","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x4929678","0x4d415449432f555344","0xac54c59f055b863a000","0x0","0x65bafc67","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x85d7684a","0x4554482f55534443","0x3b1f0fb2359e0723900","0x0","0x65bafc67","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0xf352b","0x4441492f55534443","0x57e5af636dba000","0x0","0x65bafc67","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x9ee27ee60","0x574254432f55534443","0x0"],"max_fee":"0xde0b6b3a7640000","version":"0x1","signature":["0xa8d6fbf01d2b71ef369f3f36bb64efc8c7ce4f5b54431829a53be84ee74f98","0x2dee12e5f9f5ab7f06b4414e3c6ad67cd43c6d959686d7e2ad756384e1f3610"],"nonce":"0x52cec"},{"transaction_hash":"0x195b32eb6b194644704510feb4456c9a17a46d8e14b0942614ba643227ba2f5","type":"INVOKE","sender_address":"0x35acd6dd6c5045d18ca6d0192af46b335a5402c02d41f46e4e77ea2c951d9a3","calldata":["0x1","0x6359ed638df79b82f2f9dbf92abbcb41b57f9dd91ead86b1c85d2dee192c","0xf818e4530ec36b83dfe702489b4df537308c3b798b0cc120e32c2056d68b7d","0x0"],"max_fee":"0x2386f26fc10000","version":"0x1","signature":["0x28c06db7e037dd52690bace4596261d574a6395d8c4a491da92ba323d263542","0x1467fd0fdcad340a07a203397486810ab2f7b96b0df527076e51e9a5e415913"],"nonce":"0x10fae"},{"transaction_hash":"0x14d597cf5038b13322f8e1642dcaa3c17d1a0fe8a094578f7751406c73cbad7","type":"INVOKE","sender_address":"0x641805d0186ac15797749dbce7c1d5205c1a36db2f2f29d1fb9b1dbbf338085","calldata":["0x1","0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7","0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e","0x3","0x5cbb57d024bcf68552e3c00fb265f029ec3ddeae","0x38d7ea4c68000","0x0"],"max_fee":"0x3d130d601b3","version":"0x1","signature":["0x7d50d0bb582e6d82fc05c0d6ce22407fb5ff852ab20986c7300eb09d5b9e613","0x35904e1e594006ce4e43926f5e1c54ea9914c6638fa183a2c7583c62b9faba6"],"nonce":"0x1c7"},{"transaction_hash":"0x79bf342c36f87f9cc68a68e61ab6d3250f99a757e44c0952577f8db132a2cf5","type":"INVOKE","sender_address":"0x2cc8bac39db78385a226bef323f8cdc7fbb40525a0b4ab8181432543f233530","calldata":["0x1","0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7","0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e","0x0","0x3","0x3","0x618623c1461d9e8444629772b12e30ec85f04eab291a8e2abd82a5b4a2bd095","0x71afd498d0000","0x0"],"max_fee":"0x25f7854e94a2","version":"0x1","signature":["0x4e391e01dfabae4d56036900b37cd5fe2253f9b3110908eadbe299614e8baea","0x204a5a8e6bde59a9fba2363affebbac4cd30aec47031701152bcdaab8dd31f"],"nonce":"0x2a335"},{"transaction_hash":"0x3f93ee5dd36bec0e9e2d79c6a0d79b91b54ae6b105897e7bedff925caef9a20","type":"INVOKE","sender_address":"0x1d8e01188c4c8984fb19f00156491787e64fd2de1c3ce4eb9571924c540cf3b","calldata":["0x1","0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167","0x3d0bcca55c118f88a08e0fcc06f43906c0c174feb52ebc83f0fa28a1f59ed67","0x0","0x63","0x63","0xe","0x0","0x65bafc83","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x3d1a6979480","0x4254432f555344","0x228f943ba9935b5518000","0x0","0x65bafc83","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x5f48e60","0x574254432f425443","0x46fe202604c000","0x0","0x65bafc83","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x3d0cda19680","0x574254432f555344","0x2d7c66f0a11b8d0000","0x0","0x65bafc83","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x387e22bf580","0x4254432f455552","0xfb3a0fd7eea9dda8000","0x0","0x65bafc83","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x3441d3d0e0","0x4554482f555344","0xadc5375dfb307d1fc000","0x0","0x65bafc83","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x2305a6b4a","0x534f4c2f555344","0xd2f31afa2e0c91c80800","0x0","0x65bafc83","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x5ee61ba","0x4441492f555344","0x1a81fa4f0f950d72a00","0x0","0x65bafc83","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x233c40d5","0x554e492f555344","0x610bc986b611998700","0x0","0x65bafc83","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0xf4047","0x555344542f555344","0xb90a4a8751e959e40","0x0","0x65bafc83","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0xf422e","0x555344432f555344","0xe9c1d0056b102600","0x0","0x65bafc83","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x4918506","0x4d415449432f555344","0xac3c86356f296663800","0x0","0x65bafc83","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x85c3440a","0x4554482f55534443","0x3b17f0fed7718c15780","0x0","0x65bafc83","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0xf352b","0x4441492f55534443","0x57e5af636dba000","0x0","0x65bafc83","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x9ee27ee60","0x574254432f55534443","0x0"],"max_fee":"0xde0b6b3a7640000","version":"0x1","signature":["0x5ed9541f86fabf45a85fcd4d67a563feccdd85fcfa182d49f5c50d45c5fdba9","0x35baf7dda894c1f3eb66a21a7b7d75184394119d91ecc5afb49d9827e15f67a"],"nonce":"0x52ced"},{"transaction_hash":"0x1d172e6042dce68774f484fda19c908caad9f9f7d61c41adea99bf762c53805","type":"INVOKE","sender_address":"0x23010788ae442014c87605e0ce4ce787eb15489176f8e286f8e3b06f6d68d9","calldata":["0x1","0x71d07b1217cdcc334739a3f28da75db05d62672ad04b9204ee11b88f2f9f61c","0x2d1af4265f4530c75b41282ed3b71617d3d435e96fe13b08848482173692f4f","0x2","0x101d","0x0"],"max_fee":"0x110d9316ec000","version":"0x1","signature":["0x7d939c57140e62b6c4636f5e67b1ba69f208cf9c931544657bd13320f161f29","0x20350ef62fa837838714737e69e44cca61deec23557bc28d2453203b4bb7612"],"nonce":"0x5"},{"transaction_hash":"0x26e3b90c4777a07c4047f8d1e59fea60adabf713f8f8c4257daafb398cf16b7","type":"INVOKE","sender_address":"0x4afc1995e0606c2371bbd336e13eec14a3066234025f01d56f067717ce7a910","calldata":["0x2","0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7","0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e","0x0","0x3","0x5e367ac160e5f90c5775089b582dfc987dd148a5a2f977c49def2a6644f724b","0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e","0x3","0x3","0x6","0x382f5964d3eaf67d0cfcf1f26450fdf2cd7e2dd76fa4f4c0ae2295284abd6f7","0x38d7ea4c68000","0x0","0x382f5964d3eaf67d0cfcf1f26450fdf2cd7e2dd76fa4f4c0ae2295284abd6f7","0x15af1d78b58c40000","0x0"],"max_fee":"0x82f79cd9000","version":"0x1","signature":["0x6aad1d713ca295249d7c68ac2044e4dcbac5fdc595f7ad84a25713b3e9172ed","0x6bac9a4ee6537d44a7fce07cfff934c89bf103b7d46acdac1ce132bd4db34fa"],"nonce":"0x2"},{"transaction_hash":"0x597ea6a78d0bf20513d516616e4c1ab8d8edf7470a22d1d4093f6c5612f11ae","type":"INVOKE","sender_address":"0x23010788ae442014c87605e0ce4ce787eb15489176f8e286f8e3b06f6d68d9","calldata":["0x1","0x71d07b1217cdcc334739a3f28da75db05d62672ad04b9204ee11b88f2f9f61c","0x2d1af4265f4530c75b41282ed3b71617d3d435e96fe13b08848482173692f4f","0x2","0x101d","0x1"],"max_fee":"0x110d9316ec000","version":"0x1","signature":["0x70525b1f9363d256eca49857499e3fe7cd08bf843e3be059576591bfa4dbfe9","0x3b5f034c9c95d1384531986fd175aa14bd5102616811a97e11de43a5890ae3d"],"nonce":"0x6"},{"transaction_hash":"0x574ab17bc002fcd4782fe00c0ad8a716b4b96d52269d1fcafc1e19c1fe3ca74","type":"DEPLOY_ACCOUNT","max_fee":"0x121b31f0e51c","version":"0x1","signature":["0x6e4297756328f1345849ccde6614728b59e224d78f115c44b7b63f68bdbe052","0x17174014aeb3e002b4f1939266bd97cf246a27119084d08768edb0fb49b8cf4"],"nonce":"0x0","contract_address_salt":"0x60d56fc9887c7c66709c05208e5109f48091191fc10b3aac04cf2d627f772b4","constructor_calldata":["0x60d56fc9887c7c66709c05208e5109f48091191fc10b3aac04cf2d627f772b4","0x4afc1995e0606c2371bbd336e13eec14a3066234025f01d56f067717ce7a910"],"class_hash":"0x715b5e10bf63c36e69c402a81e1eb96b9107ef56eb5e821b00893e39bdcf545"},{"transaction_hash":"0x55bfb64c4869f3cd325d12263a609132161d7ecb58269400e385914edc71a5d","type":"INVOKE","sender_address":"0x342dacf32f4c403a400c9b2a9e9f36c5dcdf88223da58393d660bfd2020d248","calldata":["0x1","0x71d07b1217cdcc334739a3f28da75db05d62672ad04b9204ee11b88f2f9f61c","0xf2f7c15cbe06c8d94597cd91fd7f3369eae842359235712def5584f8d270cd","0x12","0x13c3","0x3","0x0","0x0","0x0","0x0","0x0","0x1","0x0","0x4","0x65","0x1","0x60","0x1","0x58","0x1","0x53","0x1"],"max_fee":"0x80c8dcc9c96","version":"0x1","signature":["0x3532816126f51302cfe93152d4c17fbd32f955f5794efd304f80d708e11beb2","0x6ccf0a4b7e4f7747456a9b595c25abc9272521c5868c1c7e11a75b413f54303"],"nonce":"0x501"},{"transaction_hash":"0x72937ecb4cf5a591d90c6cb86a87c679bf499292642eec0afdb0385ee4c4d0d","type":"DEPLOY_ACCOUNT","max_fee":"0x121b31f0e51c","version":"0x1","signature":["0x31c1633a31b0ff563c96a75bb993b144a5bee0c026a66876329932b42d3f5e1","0x5e8e60aeb49097a0c581475f6af571a0d59e8fb84e800183c619eb85ca9024a"],"nonce":"0x0","contract_address_salt":"0x2b92e323c7f1d15865b68fbd00af1f7478de81f358895fdb5384113cd1dd381","constructor_calldata":["0x2b92e323c7f1d15865b68fbd00af1f7478de81f358895fdb5384113cd1dd381","0x7d0af0309fa24145caf8b5c61345080efc2055e81e43685a8ea453bcba9358"],"class_hash":"0x715b5e10bf63c36e69c402a81e1eb96b9107ef56eb5e821b00893e39bdcf545"},{"transaction_hash":"0x62d667988017a0ab2850f817cb0a0c3d8b97abdcdd432e0bec70dd011a8e739","type":"INVOKE","sender_address":"0x5341fcfe51d89d23648076ba959e7206a5d392cdcfe11608ae497939c89303f","calldata":["0x1","0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7","0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e","0x0","0x3","0x3","0x49d5a30388fb93f97377436aa1dcade76462ae648ee145b5cd0b956dbe7bc2a","0x71afd498d0000","0x0"],"max_fee":"0x25f7854e94a2","version":"0x1","signature":["0x29c4b77701a2d5ca5d4daf355b8f6249dc90ecc0c335a03fdab461e258f53fe","0x431c5a8b4cf5cf57ab7f98b644c01b635e0bc1686ec11878779ff0087a694b"],"nonce":"0x29239"},{"transaction_hash":"0x2444b020bd13bc40c1ba560bf719f0fa8c5f9693ad3d12a5c5a3f56e3a3ca14","type":"INVOKE","sender_address":"0x56f361a66ede35a178d06b17d3ec30572847fc1e883c460129d47c18bc691c7","calldata":["0x1","0x56f361a66ede35a178d06b17d3ec30572847fc1e883c460129d47c18bc691c7","0xf2f7c15cbe06c8d94597cd91fd7f3369eae842359235712def5584f8d270cd","0x0","0x3","0x3","0x1a736d6ed154502257f02b1ccdf4d9d1089f80811cd6acad48e6b6a9d1f2003","0x1","0x0"],"max_fee":"0x617803a3fa9","version":"0x1","signature":["0x4c265511de22f91fff2931c5bb1492671bb9b9af853ab167e56cb839ce47e20","0x4cf892d4d1dbbd72f04f1b791a605c3b08076d0254463e25f1f5c0c6310031d"],"nonce":"0x12"},{"transaction_hash":"0x6a41516f56f626fcf1c2286f4d3b74a39073f640114d14aa57852fc3043e51d","type":"INVOKE","sender_address":"0x2d0de52e20198e60f6e5f469a0abffe214a1126a4bd920f652ef44c203a9e84","calldata":["0x1","0x71d07b1217cdcc334739a3f28da75db05d62672ad04b9204ee11b88f2f9f61c","0xf2f7c15cbe06c8d94597cd91fd7f3369eae842359235712def5584f8d270cd","0xc","0x13c2","0x0","0x0","0x1","0x0","0x0","0x0","0x0","0x0","0x1","0x3","0x1"],"max_fee":"0x110d9316ec000","version":"0x1","signature":["0x8463517cfb7b6c25a31d585480e15bfd7694268ad088c5f53f791d8c887384","0x51e0631a1cbc3fc8d8c0afdf8ef64fe548448dc1dbd533105d2a21ecb02693c"],"nonce":"0x3"},{"transaction_hash":"0x10a16e0e152bebc7cf2bc32f771035f394dd4b55145349bf7d2a350eedce64b","type":"INVOKE","sender_address":"0x1d8e01188c4c8984fb19f00156491787e64fd2de1c3ce4eb9571924c540cf3b","calldata":["0x1","0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167","0x3d0bcca55c118f88a08e0fcc06f43906c0c174feb52ebc83f0fa28a1f59ed67","0x0","0x63","0x63","0xe","0x0","0x65bafca4","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x3d1a73a572a","0x4254432f555344","0x228f99fc9e0e2eb438e00","0x0","0x65bafca4","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x5f419cb","0x574254432f425443","0x46f8b261e4d600","0x0","0x65bafca4","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x3d083928ae0","0x574254432f555344","0x2d78f4173228ddc000","0x0","0x65bafca4","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x388346fa18a","0x4254432f455552","0xfb50ed33b7aa12b3600","0x0","0x65bafca4","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x344493801a","0x4554482f555344","0xadcd23c8d1618995fa00","0x0","0x65bafca4","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x230f817e0","0x534f4c2f555344","0xd3312acc961c4a4ee000","0x0","0x65bafca4","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x5ee61ba","0x4441492f555344","0x1a81c547ab91b3bba00","0x0","0x65bafca4","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x23519ad2","0x554e492f555344","0x6140d6764146a2c800","0x0","0x65bafca4","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0xf4047","0x555344542f555344","0xb911b0ac9f7542f80","0x0","0x65bafca4","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0xf422e","0x555344432f555344","0xe9c1d0056b102600","0x0","0x65bafca4","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x492f820","0x4d415449432f555344","0xac72ee3576c1f0de000","0x0","0x65bafca4","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x85ca21da","0x4554482f55534443","0x3b1af98f340eac63380","0x0","0x65bafca4","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0xf352b","0x4441492f55534443","0x57e5f7e780083c0","0x0","0x65bafca4","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x9ee27ee60","0x574254432f55534443","0x0"],"max_fee":"0xde0b6b3a7640000","version":"0x1","signature":["0x6d9b819175118e5f723ba468bb84b6aa47493028b4e5dbb2c31e870f22ef0f7","0x94488911e7232dbead2591e13fbbab9263dc5debecf5bbcee5849ed920f1fd"],"nonce":"0x52cee"},{"transaction_hash":"0x1a76b55c303bcbd3322b4341eee2cfc8badfc70639a476d06aafaad1fd89a78","type":"INVOKE","sender_address":"0x35acd6dd6c5045d18ca6d0192af46b335a5402c02d41f46e4e77ea2c951d9a3","calldata":["0x1","0x3fe8e4571772bbe0065e271686bd655efd1365a5d6858981e582f82f2c10313","0x1136789e1c76159d9b9eca06fcef05bdcf77f5d51bd4d9e09f2bc8d7520d8e6","0x2","0x42bf11595ab0f8cc9e3c109c44962f3f","0xa09ee0ba8694ef81a5382825afcedd0"],"max_fee":"0x22b1c8c1227a00000","version":"0x1","signature":["0x3a6a062d2be1a60961cbe12ebf61bf0801c8144fb853cd88da17a3e996f433d","0x78c8d08e0848d1e930d4cba5be817da488b3d517ebffe8857c24cd8f89fb854"],"nonce":"0x10faf"},{"transaction_hash":"0x5f39efe63b7d7e511a55242964d11b8539a823e3f543bdc4e21aa7c4b9f700b","type":"INVOKE","sender_address":"0x1e6cac1e9865c80fa03cf77b24cfde519ada323c363250a9b07b2bc71c05cef","calldata":["0x1","0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7","0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e","0x0","0x3","0x3","0x744d4ba0b9e4a512b1667dcf3f47dc830427dbb8a2e44f5b9bac7736d07e290","0x71afd498d0000","0x0"],"max_fee":"0x25f7854e94a2","version":"0x1","signature":["0x1fa0457a5a3276c1991c42124e7a5306f0eb4f2057936ebcbedebefe36006a","0x188d46913ba6677210cbf4b842903efe9d4f4f77cc18ccdab49f6f403b2efc9"],"nonce":"0x27339"},{"transaction_hash":"0x4fe05bd3e218c1981dcfb49b4d4593c77b3302f659ee2c66d528f84f741373b","type":"INVOKE","sender_address":"0x57ee8875294918c83d06e47f63d2258241c7e04a392a66df695b76da2e03020","calldata":["0x1","0x57ee8875294918c83d06e47f63d2258241c7e04a392a66df695b76da2e03020","0xf2f7c15cbe06c8d94597cd91fd7f3369eae842359235712def5584f8d270cd","0x0","0x3","0x3","0x1a736d6ed154502257f02b1ccdf4d9d1089f80811cd6acad48e6b6a9d1f2003","0x1","0x0"],"max_fee":"0x6178036a9f2","version":"0x1","signature":["0x1e3d9b2a65b485c224afcbae4e6b803de817d16ddf1d5c75b84b5f7b1cb27fd","0x763248a6420e1a469c7b0a01b93658e9bf2a99e2cbb10fefd26916fbb3945f3"],"nonce":"0x0"},{"transaction_hash":"0x324cbfd26c89e2a058120fbd93f3058192b289315753918129dd54ca8dae28d","type":"INVOKE","sender_address":"0x7d0af0309fa24145caf8b5c61345080efc2055e81e43685a8ea453bcba9358","calldata":["0x2","0x5bc1671cfca907bf213e04acf08b1f5367aa564fa28f9f154f920cb45002dff","0x335f4be7a6745c95f27d2222d0349d426ebfe66d2d40874abb0b47cce9c783f","0x3","0x1","0x71d07b1217cdcc334739a3f28da75db05d62672ad04b9204ee11b88f2f9f61c","0x1","0x5bc1671cfca907bf213e04acf08b1f5367aa564fa28f9f154f920cb45002dff","0x22b342738693c44dc4cdfba2e13456232c8528a2ec23b2222be17bd91a9addb","0xd","0x4","0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7","0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e","0x1","0x5e367ac160e5f90c5775089b582dfc987dd148a5a2f977c49def2a6644f724b","0x219209e083275171774dab1df80982e9df2096516f06319c5c6d71ae0a8480c","0x1","0x5e367ac160e5f90c5775089b582dfc987dd148a5a2f977c49def2a6644f724b","0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e","0x1","0x5e367ac160e5f90c5775089b582dfc987dd148a5a2f977c49def2a6644f724b","0x2f0b3c5710379609eb5495f1ecd348cb28167711b73609fe565a72734550354","0x1"],"max_fee":"0xe8be5bab7e8","version":"0x1","signature":["0x59f225bad7c81608b2fe7763d345fac19474f3306910223f1a2a5fb397c05e8","0x7926c0e1b21212b2187bf69b7cbb93f3dc521c256950764d52e5a487bb9e34a"],"nonce":"0x3"},{"transaction_hash":"0x7cf5aa469fe49cb3ba8e36713d44b4e244182d9545dfc27aa1ab8c624572fcd","type":"INVOKE","sender_address":"0x4afc1995e0606c2371bbd336e13eec14a3066234025f01d56f067717ce7a910","calldata":["0x2","0x382f5964d3eaf67d0cfcf1f26450fdf2cd7e2dd76fa4f4c0ae2295284abd6f7","0x335f4be7a6745c95f27d2222d0349d426ebfe66d2d40874abb0b47cce9c783f","0x0","0x3","0x382f5964d3eaf67d0cfcf1f26450fdf2cd7e2dd76fa4f4c0ae2295284abd6f7","0x22b342738693c44dc4cdfba2e13456232c8528a2ec23b2222be17bd91a9addb","0x3","0xd","0x10","0x1","0x71d07b1217cdcc334739a3f28da75db05d62672ad04b9204ee11b88f2f9f61c","0x1","0x4","0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7","0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e","0x1","0x5e367ac160e5f90c5775089b582dfc987dd148a5a2f977c49def2a6644f724b","0x219209e083275171774dab1df80982e9df2096516f06319c5c6d71ae0a8480c","0x1","0x5e367ac160e5f90c5775089b582dfc987dd148a5a2f977c49def2a6644f724b","0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e","0x1","0x5e367ac160e5f90c5775089b582dfc987dd148a5a2f977c49def2a6644f724b","0x2f0b3c5710379609eb5495f1ecd348cb28167711b73609fe565a72734550354","0x1"],"max_fee":"0xbd2cc61d000","version":"0x1","signature":["0x5e65e9f66dd22c84432ace4ac22b8339634b3d832d36687b91663f03036291a","0x1a19e782a8e2b0f71a0fbc2f419822f8b5ba18f380e6490d864a7adab0c7780"],"nonce":"0x3"},{"transaction_hash":"0x78ac2619361a13f4eb5d6e09dcffa856674bdd1862142508acab0f8fc9dc342","type":"DEPLOY_ACCOUNT","max_fee":"0xabf2003327c","version":"0x1","signature":["0x37f88d93dc398b8eb5fd4472fd9eb6830e46651504ff58a5b97aa7325ce85ad","0x63604cb8f6d54d4a6b476ff85a945a8759db21903973519246f78c349bf6df7"],"nonce":"0x0","contract_address_salt":"0x4816c93b65dbce3bb9290ff6e690f8da71bb57330f49ac48206aae25faeb82c","constructor_calldata":["0x33434ad846cdd5f23eb73ff09fe6fddd568284a0fb7d1be20ee482f044dabe2","0x79dc0da7c54b95f10aa182ad0a46400db63156920adb65eca2654c0945a463","0x2","0x4816c93b65dbce3bb9290ff6e690f8da71bb57330f49ac48206aae25faeb82c","0x0"],"class_hash":"0x25ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918"},{"transaction_hash":"0x1cfdb937038468b271c2f1cc6e7d86ee66ba16ce238eb56a50f0c61909f6013","type":"INVOKE","sender_address":"0x618623c1461d9e8444629772b12e30ec85f04eab291a8e2abd82a5b4a2bd095","calldata":["0x1","0x5e367ac160e5f90c5775089b582dfc987dd148a5a2f977c49def2a6644f724b","0x2f0b3c5710379609eb5495f1ecd348cb28167711b73609fe565a72734550354","0x0","0x3","0x3","0x618623c1461d9e8444629772b12e30ec85f04eab291a8e2abd82a5b4a2bd095","0x21e19e0c9bab240000","0x0"],"max_fee":"0x8825dbcdbd5","version":"0x1","signature":["0x16ee9e37c6fcde131e1ebe8c91493b5d3733b650bb814494e581d6f01e3e4cc","0x6b4dea6654c5d4331553044d10686d3d9e96360638bf637f11f5591edd814c7"],"nonce":"0x1"},{"transaction_hash":"0x63c7c2227326de33dfb7b72b6f00c9c2bcc5a05f9d555dd5178a10c253539fb","type":"INVOKE","sender_address":"0x1d8e01188c4c8984fb19f00156491787e64fd2de1c3ce4eb9571924c540cf3b","calldata":["0x1","0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167","0x3d0bcca55c118f88a08e0fcc06f43906c0c174feb52ebc83f0fa28a1f59ed67","0x0","0x63","0x63","0xe","0x0","0x65bafcb3","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x3d1d3e6cd8a","0x4254432f555344","0x22929a8ba5cecc9a5f800","0x0","0x65bafcb3","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x5f3d42a","0x574254432f425443","0x46f5745755d400","0x0","0x65bafcb3","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x3d083928ae0","0x574254432f555344","0x2d78f4173228ddc000","0x0","0x65bafcb3","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x38843e4be60","0x4254432f455552","0xfb55390c547c895a000","0x0","0x65bafcb3","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x3446541bda","0x4554482f555344","0xaddb7c91ec90858df000","0x0","0x65bafcb3","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x2315dd18a","0x534f4c2f555344","0xd36e2f3046f161f4fc00","0x0","0x65bafcb3","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x5ee606d","0x4441492f555344","0x1a81768d5dd8b330000","0x0","0x65bafcb3","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x23532140","0x554e492f555344","0x614853c035959a0000","0x0","0x65bafcb3","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0xf4047","0x555344542f555344","0xb9125af2b04fc2240","0x0","0x65bafcb3","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0xf422e","0x555344432f555344","0xe9c1d0056b102600","0x0","0x65bafcb3","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x49430a0","0x4d415449432f555344","0xaca30806f991b506000","0x0","0x65bafcb3","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x85cc7f52","0x4554482f55534443","0x3b1c050ae22e0a00d80","0x0","0x65bafcb3","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0xf352b","0x4441492f55534443","0x57ea9d2a45d8140","0x0","0x65bafcb3","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x9ee27ee60","0x574254432f55534443","0x0"],"max_fee":"0xde0b6b3a7640000","version":"0x1","signature":["0x5020821e648819e83f895873285cb7aa90442587e16951a5e3cd3e224b025d5","0x4514030048b17962304aeffd1325771d87a33b6c18b17ca48dc504a7978b9fd"],"nonce":"0x52cef"},{"transaction_hash":"0x525902ba53d0913e3bf0c8241216b5c596cc9549f56e88d0c13e0f2782a48af","type":"INVOKE","sender_address":"0x2d0de52e20198e60f6e5f469a0abffe214a1126a4bd920f652ef44c203a9e84","calldata":["0x1","0x71d07b1217cdcc334739a3f28da75db05d62672ad04b9204ee11b88f2f9f61c","0x1f64d317ff277789ba74de95db50418ab0fa47c09241400b7379b50d6334c3a","0x2","0x13c2","0x1"],"max_fee":"0x110d9316ec000","version":"0x1","signature":["0x52dad164ef786c4f50e7fc8ba621f797001a853b0149217a7c92caace92514b","0x162be62a6aa2f6d008f77642b864356caf1b8e4f55b089a7bd55258efa8f7e9"],"nonce":"0x4"},{"transaction_hash":"0x1a75d128cfb918457df3bebfcd6482ac0024bccf0366bed566a4e3e7359b144","type":"INVOKE","sender_address":"0x342dacf32f4c403a400c9b2a9e9f36c5dcdf88223da58393d660bfd2020d248","calldata":["0x1","0x71d07b1217cdcc334739a3f28da75db05d62672ad04b9204ee11b88f2f9f61c","0x1f64d317ff277789ba74de95db50418ab0fa47c09241400b7379b50d6334c3a","0x2","0x13c3","0x1"],"max_fee":"0x7ccc135dd3c","version":"0x1","signature":["0x3e4a254e3babf13ced173127fd00371cf4b353dee9c6d4c7cf13140ee79d0fb","0x23be35a19fe0609fac0d4fa513f8900fc6ac9e9065e7d506d6aef8eaafb0f4f"],"nonce":"0x502"},{"transaction_hash":"0x5645389859781ef85b6e8796f06358ab0976847b9b2f43c4de0ef2c1b8f3dbe","type":"INVOKE","sender_address":"0x557720734716101ec8779eb3f394b982b6a778603794802f16108251a848b8a","calldata":["0x1","0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7","0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e","0x0","0x3","0x3","0x48781f51b431a9eed10277eb0a94b4a22383f346b1c127f19ceb4afb02a4eee","0x71afd498d0000","0x0"],"max_fee":"0x25f7854e94a2","version":"0x1","signature":["0x556bcbd87dcecc20a87273a16020de9cc340b2ae9d082a066b84dd169b217b6","0x7e447d301bb4455bebae725a06357814af54e544695943fed171b204d63cd36"],"nonce":"0x2c82a"},{"transaction_hash":"0x6d7904c6fec4df7b9e46c55a18139b21072e3f0bb662ef804eaf776dd7477e","type":"INVOKE","sender_address":"0x574bd20a5f65a466b37d8f49f0116f9f2d2cee29248837a09a7e3407a0fa298","calldata":["0x1","0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d","0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e","0x0","0x3","0x3","0x49d5a30388fb93f97377436aa1dcade76462ae648ee145b5cd0b956dbe7bc2a","0x71afd498d0000","0x0"],"max_fee":"0x3fc74215b5e6","version":"0x1","signature":["0x766087d8ad1af19c02c81f2ecf387934787ce0b4d71e75ae0e03900b137574a","0x2a0eafe73823fa77beafac6b509366aef553676f2ecda3a0045f0d113c8aea1"],"nonce":"0x2a8a7"},{"transaction_hash":"0x472cc4a1ae1a9727d42c5992ddb453b4f6139b4f262a2f5af14dd2a598417fc","type":"INVOKE","sender_address":"0x1d8e01188c4c8984fb19f00156491787e64fd2de1c3ce4eb9571924c540cf3b","calldata":["0x1","0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167","0x3d0bcca55c118f88a08e0fcc06f43906c0c174feb52ebc83f0fa28a1f59ed67","0x0","0x63","0x63","0xe","0x0","0x65bafcc3","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x3d1bcdd47ea","0x4254432f555344","0x22933643cbf4e58912200","0x0","0x65bafcc3","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x5f3f811","0x574254432f425443","0x46f7205497e200","0x0","0x65bafcc3","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x3d083928ae0","0x574254432f555344","0x2d78f4173228ddc000","0x0","0x65bafcc3","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x3882cad7200","0x4254432f455552","0xfb4ec5288ebda4e0000","0x0","0x65bafcc3","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x3445e9ce50","0x4554482f555344","0xaddb529875c7e5e7d000","0x0","0x65bafcc3","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x230c2b000","0x534f4c2f555344","0xd336416cae45bfd00000","0x0","0x65bafcc3","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x5ee606d","0x4441492f555344","0x1a814a5c94319e2fc00","0x0","0x65bafcc3","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x23687b3d","0x554e492f555344","0x618b5f4c4ce3424a00","0x0","0x65bafcc3","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0xf4047","0x555344542f555344","0xb91238dbf2e53b840","0x0","0x65bafcc3","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0xf422e","0x555344432f555344","0xe9c1d0056b102600","0x0","0x65bafcc3","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x49457b0","0x4d415449432f555344","0xaca8c8cc9519167d000","0x0","0x65bafcc3","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x85cdebe8","0x4554482f55534443","0x3b219e2dd9ddc85de00","0x0","0x65bafcc3","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0xf3546","0x4441492f55534443","0x57eb3940eae0680","0x0","0x65bafcc3","0x534b594e45545f54524144494e47","0x534b594e45545f54524144494e47","0x9ee27ee60","0x574254432f55534443","0x0"],"max_fee":"0xde0b6b3a7640000","version":"0x1","signature":["0xd1ca0b29720454cc21b10eb572b926d7e10d5835902b4d02958f8503e957e6","0x4fcecffd0386399b3cf5f1414ad7188cda680505b61bf47a7982250f0404d87"],"nonce":"0x52cf0"}]}"#;

    static EVENTS_PAGE: &str = r#"{
        "id": 1,
        "jsonrpc": "2.0",
        "result": {
          "events": [
            {
              "block_hash": "0x780cea3e1af61f818a184db7a8ebed6fd48949d35ff51e46a0c09257f84160c",
              "block_number": 942701,
              "data": [
                "0x65bafc10",
                "0x534b594e45545f54524144494e47",
                "0x534b594e45545f54524144494e47",
                "0x3d2bdffb26a",
                "0x4254432f555344",
                "0x2285844799992c4770200"
              ],
              "from_address": "0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167",
              "keys": [
                "0x280bb2099800026f90c334a3a23888ffe718a2920ffbbf4f44c6d3d5efb613c"
              ],
              "transaction_hash": "0x661476527e056e48c280410c3bd2ec014da16cc8cf8c84961205c8896aa1799"
            },
            {
              "block_hash": "0x780cea3e1af61f818a184db7a8ebed6fd48949d35ff51e46a0c09257f84160c",
              "block_number": 942701,
              "data": [
                "0x65bafc10",
                "0x534b594e45545f54524144494e47",
                "0x534b594e45545f54524144494e47",
                "0x5f40ac8",
                "0x574254432f425443",
                "0x46f7ff6dc39000"
              ],
              "from_address": "0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167",
              "keys": [
                "0x280bb2099800026f90c334a3a23888ffe718a2920ffbbf4f44c6d3d5efb613c"
              ],
              "transaction_hash": "0x661476527e056e48c280410c3bd2ec014da16cc8cf8c84961205c8896aa1799"
            },
            {
              "block_hash": "0x780cea3e1af61f818a184db7a8ebed6fd48949d35ff51e46a0c09257f84160c",
              "block_number": 942701,
              "data": [
                "0x65bafc10",
                "0x534b594e45545f54524144494e47",
                "0x534b594e45545f54524144494e47",
                "0x3d19063ae60",
                "0x574254432f555344",
                "0x2d8578a36abc44c000"
              ],
              "from_address": "0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167",
              "keys": [
                "0x280bb2099800026f90c334a3a23888ffe718a2920ffbbf4f44c6d3d5efb613c"
              ],
              "transaction_hash": "0x661476527e056e48c280410c3bd2ec014da16cc8cf8c84961205c8896aa1799"
            },
            {
              "block_hash": "0x780cea3e1af61f818a184db7a8ebed6fd48949d35ff51e46a0c09257f84160c",
              "block_number": 942701,
              "data": [
                "0x65bafc10",
                "0x534b594e45545f54524144494e47",
                "0x534b594e45545f54524144494e47",
                "0x3890fdc51e0",
                "0x4254432f455552",
                "0xfb8de9ed8e321122000"
              ],
              "from_address": "0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167",
              "keys": [
                "0x280bb2099800026f90c334a3a23888ffe718a2920ffbbf4f44c6d3d5efb613c"
              ],
              "transaction_hash": "0x661476527e056e48c280410c3bd2ec014da16cc8cf8c84961205c8896aa1799"
            },
            {
              "block_hash": "0x780cea3e1af61f818a184db7a8ebed6fd48949d35ff51e46a0c09257f84160c",
              "block_number": 942701,
              "data": [
                "0x65bafc10",
                "0x534b594e45545f54524144494e47",
                "0x534b594e45545f54524144494e47",
                "0x3455422e60",
                "0x4554482f555344",
                "0xae3421e84e434e8d0000"
              ],
              "from_address": "0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167",
              "keys": [
                "0x280bb2099800026f90c334a3a23888ffe718a2920ffbbf4f44c6d3d5efb613c"
              ],
              "transaction_hash": "0x661476527e056e48c280410c3bd2ec014da16cc8cf8c84961205c8896aa1799"
            },
            {
              "block_hash": "0x780cea3e1af61f818a184db7a8ebed6fd48949d35ff51e46a0c09257f84160c",
              "block_number": 942701,
              "data": [
                "0x65bafc10",
                "0x534b594e45545f54524144494e47",
                "0x534b594e45545f54524144494e47",
                "0x231b6d400",
                "0x534f4c2f555344",
                "0xd33ff5f2bf5654440000"
              ],
              "from_address": "0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167",
              "keys": [
                "0x280bb2099800026f90c334a3a23888ffe718a2920ffbbf4f44c6d3d5efb613c"
              ],
              "transaction_hash": "0x661476527e056e48c280410c3bd2ec014da16cc8cf8c84961205c8896aa1799"
            },
            {
              "block_hash": "0x780cea3e1af61f818a184db7a8ebed6fd48949d35ff51e46a0c09257f84160c",
              "block_number": 942701,
              "data": [
                "0x65bafc10",
                "0x534b594e45545f54524144494e47",
                "0x534b594e45545f54524144494e47",
                "0x5ee606d",
                "0x4441492f555344",
                "0x1a898ce178794b15500"
              ],
              "from_address": "0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167",
              "keys": [
                "0x280bb2099800026f90c334a3a23888ffe718a2920ffbbf4f44c6d3d5efb613c"
              ],
              "transaction_hash": "0x661476527e056e48c280410c3bd2ec014da16cc8cf8c84961205c8896aa1799"
            },
            {
              "block_hash": "0x780cea3e1af61f818a184db7a8ebed6fd48949d35ff51e46a0c09257f84160c",
              "block_number": 942701,
              "data": [
                "0x65bafc10",
                "0x534b594e45545f54524144494e47",
                "0x534b594e45545f54524144494e47",
                "0x23532140",
                "0x554e492f555344",
                "0x614436fdefe93bc000"
              ],
              "from_address": "0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167",
              "keys": [
                "0x280bb2099800026f90c334a3a23888ffe718a2920ffbbf4f44c6d3d5efb613c"
              ],
              "transaction_hash": "0x661476527e056e48c280410c3bd2ec014da16cc8cf8c84961205c8896aa1799"
            },
            {
              "block_hash": "0x780cea3e1af61f818a184db7a8ebed6fd48949d35ff51e46a0c09257f84160c",
              "block_number": 942701,
              "data": [
                "0x65bafc10",
                "0x534b594e45545f54524144494e47",
                "0x534b594e45545f54524144494e47",
                "0xf4047",
                "0x555344542f555344",
                "0xb90121e62630e6b40"
              ],
              "from_address": "0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167",
              "keys": [
                "0x280bb2099800026f90c334a3a23888ffe718a2920ffbbf4f44c6d3d5efb613c"
              ],
              "transaction_hash": "0x661476527e056e48c280410c3bd2ec014da16cc8cf8c84961205c8896aa1799"
            },
            {
              "block_hash": "0x780cea3e1af61f818a184db7a8ebed6fd48949d35ff51e46a0c09257f84160c",
              "block_number": 942701,
              "data": [
                "0x65bafc10",
                "0x534b594e45545f54524144494e47",
                "0x534b594e45545f54524144494e47",
                "0xf422e",
                "0x555344432f555344",
                "0xe9c3d583ab783180"
              ],
              "from_address": "0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167",
              "keys": [
                "0x280bb2099800026f90c334a3a23888ffe718a2920ffbbf4f44c6d3d5efb613c"
              ],
              "transaction_hash": "0x661476527e056e48c280410c3bd2ec014da16cc8cf8c84961205c8896aa1799"
            },
            {
              "block_hash": "0x780cea3e1af61f818a184db7a8ebed6fd48949d35ff51e46a0c09257f84160c",
              "block_number": 942701,
              "data": [
                "0x65bafc10",
                "0x534b594e45545f54524144494e47",
                "0x534b594e45545f54524144494e47",
                "0x4955596",
                "0x4d415449432f555344",
                "0xac8c72d6533190b3000"
              ],
              "from_address": "0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167",
              "keys": [
                "0x280bb2099800026f90c334a3a23888ffe718a2920ffbbf4f44c6d3d5efb613c"
              ],
              "transaction_hash": "0x661476527e056e48c280410c3bd2ec014da16cc8cf8c84961205c8896aa1799"
            },
            {
              "block_hash": "0x780cea3e1af61f818a184db7a8ebed6fd48949d35ff51e46a0c09257f84160c",
              "block_number": 942701,
              "data": [
                "0x65bafc10",
                "0x534b594e45545f54524144494e47",
                "0x534b594e45545f54524144494e47",
                "0x85e93595",
                "0x4554482f55534443",
                "0x3b2619423159a897280"
              ],
              "from_address": "0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167",
              "keys": [
                "0x280bb2099800026f90c334a3a23888ffe718a2920ffbbf4f44c6d3d5efb613c"
              ],
              "transaction_hash": "0x661476527e056e48c280410c3bd2ec014da16cc8cf8c84961205c8896aa1799"
            },
            {
              "block_hash": "0x780cea3e1af61f818a184db7a8ebed6fd48949d35ff51e46a0c09257f84160c",
              "block_number": 942701,
              "data": [
                "0x65bafc10",
                "0x534b594e45545f54524144494e47",
                "0x534b594e45545f54524144494e47",
                "0xf3546",
                "0x4441492f55534443",
                "0x57e799065d6a680"
              ],
              "from_address": "0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167",
              "keys": [
                "0x280bb2099800026f90c334a3a23888ffe718a2920ffbbf4f44c6d3d5efb613c"
              ],
              "transaction_hash": "0x661476527e056e48c280410c3bd2ec014da16cc8cf8c84961205c8896aa1799"
            },
            {
              "block_hash": "0x780cea3e1af61f818a184db7a8ebed6fd48949d35ff51e46a0c09257f84160c",
              "block_number": 942701,
              "data": [
                "0x65bafc10",
                "0x534b594e45545f54524144494e47",
                "0x534b594e45545f54524144494e47",
                "0x9ee27ee60",
                "0x574254432f55534443",
                "0x0"
              ],
              "from_address": "0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167",
              "keys": [
                "0x280bb2099800026f90c334a3a23888ffe718a2920ffbbf4f44c6d3d5efb613c"
              ],
              "transaction_hash": "0x661476527e056e48c280410c3bd2ec014da16cc8cf8c84961205c8896aa1799"
            },
            {
              "block_hash": "0x780cea3e1af61f818a184db7a8ebed6fd48949d35ff51e46a0c09257f84160c",
              "block_number": 942701,
              "data": [
                "0x1d8e01188c4c8984fb19f00156491787e64fd2de1c3ce4eb9571924c540cf3b",
                "0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8",
                "0x109a17cd79c2",
                "0x0"
              ],
              "from_address": "0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
              "keys": [
                "0x99cd8bde557814842a3121e8ddfd433a539b8c9f14bf31ebf108d12e6196e9"
              ],
              "transaction_hash": "0x661476527e056e48c280410c3bd2ec014da16cc8cf8c84961205c8896aa1799"
            },
            {
              "block_hash": "0x780cea3e1af61f818a184db7a8ebed6fd48949d35ff51e46a0c09257f84160c",
              "block_number": 942701,
              "data": [
                "0x65bafc16",
                "0x464c4f574445534b",
                "0x464c4f574445534b",
                "0x3d1d9e6c7d2",
                "0x4254432f555344",
                "0x0"
              ],
              "from_address": "0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167",
              "keys": [
                "0x280bb2099800026f90c334a3a23888ffe718a2920ffbbf4f44c6d3d5efb613c"
              ],
              "transaction_hash": "0x563ac15c24ddad96b4e36cb7fbcb521c2c6c6d9741028deb6eb1af060e264aa"
            },
            {
              "block_hash": "0x780cea3e1af61f818a184db7a8ebed6fd48949d35ff51e46a0c09257f84160c",
              "block_number": 942701,
              "data": [
                "0x65bafc16",
                "0x464c4f574445534b",
                "0x464c4f574445534b",
                "0x344cdeb2c5",
                "0x4554482f555344",
                "0x0"
              ],
              "from_address": "0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167",
              "keys": [
                "0x280bb2099800026f90c334a3a23888ffe718a2920ffbbf4f44c6d3d5efb613c"
              ],
              "transaction_hash": "0x563ac15c24ddad96b4e36cb7fbcb521c2c6c6d9741028deb6eb1af060e264aa"
            },
            {
              "block_hash": "0x780cea3e1af61f818a184db7a8ebed6fd48949d35ff51e46a0c09257f84160c",
              "block_number": 942701,
              "data": [
                "0x65bafc16",
                "0x464c4f574445534b",
                "0x464c4f574445534b",
                "0x3cfff703fdd",
                "0x574254432f555344",
                "0x0"
              ],
              "from_address": "0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167",
              "keys": [
                "0x280bb2099800026f90c334a3a23888ffe718a2920ffbbf4f44c6d3d5efb613c"
              ],
              "transaction_hash": "0x563ac15c24ddad96b4e36cb7fbcb521c2c6c6d9741028deb6eb1af060e264aa"
            },
            {
              "block_hash": "0x780cea3e1af61f818a184db7a8ebed6fd48949d35ff51e46a0c09257f84160c",
              "block_number": 942701,
              "data": [
                "0x65bafc16",
                "0x464c4f574445534b",
                "0x464c4f574445534b",
                "0x5f31daa",
                "0x574254432f425443",
                "0x0"
              ],
              "from_address": "0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167",
              "keys": [
                "0x280bb2099800026f90c334a3a23888ffe718a2920ffbbf4f44c6d3d5efb613c"
              ],
              "transaction_hash": "0x563ac15c24ddad96b4e36cb7fbcb521c2c6c6d9741028deb6eb1af060e264aa"
            },
            {
              "block_hash": "0x780cea3e1af61f818a184db7a8ebed6fd48949d35ff51e46a0c09257f84160c",
              "block_number": 942701,
              "data": [
                "0x65bafc16",
                "0x464c4f574445534b",
                "0x464c4f574445534b",
                "0x388ccd3db54",
                "0x4254432f455552",
                "0x0"
              ],
              "from_address": "0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167",
              "keys": [
                "0x280bb2099800026f90c334a3a23888ffe718a2920ffbbf4f44c6d3d5efb613c"
              ],
              "transaction_hash": "0x563ac15c24ddad96b4e36cb7fbcb521c2c6c6d9741028deb6eb1af060e264aa"
            },
            {
              "block_hash": "0x780cea3e1af61f818a184db7a8ebed6fd48949d35ff51e46a0c09257f84160c",
              "block_number": 942701,
              "data": [
                "0x65bafc16",
                "0x464c4f574445534b",
                "0x464c4f574445534b",
                "0xf3f31",
                "0x555344542f555344",
                "0x0"
              ],
              "from_address": "0x6df335982dddce41008e4c03f2546fa27276567b5274c7d0c1262f3c2b5d167",
              "keys": [
                "0x280bb2099800026f90c334a3a23888ffe718a2920ffbbf4f44c6d3d5efb613c"
              ],
              "transaction_hash": "0x563ac15c24ddad96b4e36cb7fbcb521c2c6c6d9741028deb6eb1af060e264aa"
            }
          ]
        }
      }
  "#;
}
