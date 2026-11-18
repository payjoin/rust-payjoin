- The sender signs only the inputs of its original transaction, as BIP 78
  requires. It refuses a proposal in which any other input belongs to its
  wallet, before signing, and prints the fallback transaction instead.
