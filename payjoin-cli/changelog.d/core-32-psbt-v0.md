- Fix `send` failing against Bitcoin Core 32, which returns version 2 PSBTs
  by default. A version 0 PSBT is now requested from Core 32 and later.
