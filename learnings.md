# Learning Payjoin Through Tests

## Introduction
Testing is an excellent way to learn a new technology because:
1. Tests show real-world usage of the code
2. Tests document expected behavior
3. Tests break complex systems into understandable pieces

## Test Deep Dives

### 1. Privacy Protection Test
#### `test_privacy_based_input_selection`

##### Brain-Friendly Explanation
This test is like checking if your wallet is smart about mixing coins. Imagine you have:
- A small coin worth 5,000 sats
- A bigger coin worth 50,000 sats

The test makes sure your wallet picks coins that don't give away patterns to people watching the blockchain. It's like making sure you're not always using your biggest bills first, which would make your spending patterns obvious.

##### Technical Deep-Dive
```rust
let tx = Transaction {
    version: Version::TWO,
    lock_time: LockTime::ZERO,
    input: vec![],
    output: vec![
        TxOut { value: Amount::from_sat(5_000), script_pubkey: dummy_script.clone() },
        TxOut { value: Amount::from_sat(50_000), script_pubkey: dummy_script },
    ],
};
```
This creates a transaction with two outputs of different sizes. The test then:
1. Creates a proposal using these outputs
2. Checks if the selection algorithm avoids the "Unnecessary Input Heuristic" (UIH)
3. Verifies that inputs are chosen to maintain privacy, not just based on size

Key Learning Points:
- Bitcoin transactions can leak privacy through input selection patterns
- UIH is a blockchain analysis technique that looks for unnecessary large inputs
- Payjoin helps break these patterns by being smart about input selection

### 2. Fee Management Test
#### `test_fee_rate_based_selection`

##### Brain-Friendly Explanation
This test checks if your wallet is good at handling transaction fees. It's like making sure:
- You're not paying too much in fees
- You're not paying too little (which could make your transaction stuck)
- Nobody can trick you into paying wrong fees

##### Technical Deep-Dive
```rust
let result = provisional.finalize_proposal(
    |psbt| Ok(psbt.clone()),
    Some(FeeRate::from_sat_per_vb(2).expect("valid fee rate")),
);
```
The test verifies:
1. Minimum fee rate enforcement (2 sat/vB)
2. Protection against fee-based attacks
3. Proper fee calculation for different input types

Key Learning Points:
- Fee rates in Bitcoin are measured in satoshis per virtual byte (sat/vB)
- Different input types (P2WPKH, P2TR, etc.) have different weights
- Fee calculations must account for all input weights

### 3. Transaction Processing Test
#### `test_minimum_fee_requirements`

##### Brain-Friendly Explanation
This test makes sure the whole payjoin process works correctly. It checks:
- Both parties can add their inputs
- Fees are calculated correctly
- The final transaction is valid

##### Technical Deep-Dive
```rust
let provisional = UncheckedProposal::new(original_psbt)
    .check_broadcast_suitability(min_fee_rate)
    .unwrap()
    .check_inputs_not_owned(|_| Ok(false))
    .unwrap()
    .identify_receiver_outputs(|script| Ok(script == &tx.output[0].script_pubkey))
    .unwrap()
    .commit_outputs()
    .contribute_inputs(vec![receiver_input])
    .unwrap()
    .commit_inputs();
```
This shows the complete flow:
1. Creating an unchecked proposal
2. Validating broadcast requirements
3. Checking input ownership
4. Identifying outputs
5. Contributing inputs
6. Finalizing the transaction

Key Learning Points:
- Payjoin transactions require careful validation at each step
- The builder pattern (`check_*`, `commit_*`) ensures safety
- Error handling is crucial in financial code

## Rust Learning Points
1. **Builder Pattern**: See how methods chain together for safe construction
2. **Error Handling**: Use of `Result` and `?` operator
3. **Type System**: How Rust's type system ensures correctness
4. **Testing Practices**: Using `#[test]` attribute and assertions

## Bitcoin Protocol Learning Points
1. **Transaction Structure**: Inputs, outputs, scripts
2. **Fee Calculation**: Virtual sizes and fee rates
3. **Script Types**: P2WPKH, P2TR, P2PKH differences
4. **Privacy Considerations**: Transaction analysis and countermeasures

## Advanced Topics
1. **PSBT (Partially Signed Bitcoin Transactions)**
   - How they work
   - Why they're used in payjoin
2. **Script Weights**
   - Different input types have different weights
   - Impact on fee calculation
3. **Privacy Techniques**
   - Input selection strategies
   - Avoiding common analysis heuristics


   //For PR: uri_errors

4. **URI Error Handling Improvements**
   - **Problem**: Direct exposure of `bitcoin_uri::de::Error<PjParseError>` in the API
   
   - **Implementation Steps**:
     1. Created `PayjoinUriError` wrapper:
        - Boxed internal error to reduce size
        - Implemented standard error traits
        - Added custom error formatting
   
     2. Updated URI parsing:
        - Modified `UriExt` trait to use new error type
        - Changed return type from `Box<bitcoin_uri::Uri>` to `PayjoinUriError`
        - Improved error messages for unsupported payjoin cases
   
   - **Testing Process**:
     1. Initial test implementation:
        ```rust
        #[test]
        fn test_unsupported() {
            let uri = Uri::try_from("bitcoin:...")
            match uri.check_pj_supported() {
                // Check error message
            }
        }
        ```
   
     2. Test failures and fixes:
        - Fixed network checking by adding `assume_checked()`
        - Updated error message assertion to match exact string
        - Resolved trait implementation issues for error types
   
   - **Key Learnings**:
     1. Error wrapping patterns in Rust
     2. Network checking requirements for URIs
     3. Importance of exact error message matching in tests
     4. Handling trait bounds for error types


