use starknet_ff::FieldElement;

use super::calculate_root;

// The expected roots were calculated by the starkware-libs/cairo-lang repository. These are the
// roots of PatriciaTree objects with the same leaves.
#[test]
fn test_patricia() {
    let root =
        calculate_root(vec![FieldElement::ONE, FieldElement::TWO, FieldElement::THREE]);
    let expected_root =
        FieldElement::from_hex_be("0x231e110514ca3a27707cd6c365e00685142d43b03d26f6274db51cbfa91aa1c")
            .unwrap();
    assert_eq!(root, expected_root);
}

#[test]
fn test_edge_patricia() {
    let root = calculate_root(vec![FieldElement::ONE]);
    let expected_root =
        FieldElement::from_hex_be("0x268a9d47dde48af4b6e2c33932ed1c13adec25555abaa837c376af4ea2f8ad4")
            .unwrap();
    assert_eq!(root, expected_root);
}

#[test]
fn test_binary_patricia() {
    let root = calculate_root(vec![FieldElement::ONE, FieldElement::TWO]);
    let expected_root =
        FieldElement::from_hex_be("0x599927f1181d5633c6f680dbf039534de49c44e0b9903c5305b2582dfd6a56a")
            .unwrap();
    assert_eq!(root, expected_root);
}
