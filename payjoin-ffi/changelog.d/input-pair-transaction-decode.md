- Replace `InputPairError::InvalidTransaction(String)` with
  `InputPairError::TransactionDecode(TransactionParseError)`, the same error
  `classify_tx` returns for bytes that do not decode. Bindings that match on
  the old variant need to match the new one and read the nested
  `TransactionParseError`.
