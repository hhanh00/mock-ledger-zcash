# mock-ledger-zcash

A mock server for the Ledger Zcash hardware wallet.

Serves as an end-to-end (e2e) mocking service when testing Ledger integration from [zkool](https://github.com/zkool/zkool).

## Usage

```sh
cargo run
```

## License

MIT — see [LICENSE](LICENSE).

## Signing for zkool e2e tests

The mock automatically approves Official Ledger PCZT requests (`CLA 0xE0`,
`INS 0x52`–`0x59`) and returns real signatures derived from its BIP39 test seed.
It supports single-key P2PKH transparent inputs and Orchard/Ironwood spends.
zkool generates proofs and binding signatures and submits the resulting
transaction to Zebra. No Speculos instance or device UI is required.

```sh
cargo run -- --network regtest --seed-phrase "<regtest test mnemonic>"
```

Use the same seed and account index when funding the wallet. Import an
Official Ledger (`hw: 2`) account in zkool without a spending key, synchronize
it, then call `pay`. The mock keeps one transaction session; run clients
serially. A new PCZT header resets the session. Invalid requests return
`0x6A80` and clear the session; repeated signatures are rejected.

The wire subset supports v5/v6 transactions with no Sapling bundle or asset
extensions, `SIGHASH_ALL`, and at most 255 inputs/outputs/actions per pool.
Only the v6 Ironwood and transparent paths are covered by zkool's regtest e2e
test. This mock is a software signer with automatic approval: use test seeds
only. It does not emulate device review or the Ledger's full validation.

Local checks:

```sh
cargo test
cargo clippy --all-targets -- -D warnings
```

With the mock on port 9999 and the mnemonic from zkool's `ledger_official_sign`
test, run from zkool:

```sh
ZEMU_MOCK=1 cargo test -p rlz --no-default-features --features zemu \
  -- --ignored --nocapture ledger_official_sign
```

For the Zebra-backed test, bootstrap regtest above NU6.3 activation and fund
`EXPECTED_LEDGER_ADDRESS` with Ironwood ZEC. Then run from zkool's `tests/`:

```sh
REGTEST_SEED="<mock seed>" \
EXPECTED_LEDGER_ADDRESS="<funded ironwood address>" \
EXPECTED_LEDGER_TRANSPARENT="<mock transparent address>" \
ZKOOL_BINARY="/absolute/path/to/zkool_graphql" \
uv run pytest tests/test_ledger.py -v -s
```

The GraphQL binary must be built with `graphql,zemu`. `ZEMU_PORT`, `LWD_URL`,
and `RPC_URL` can override the default mock, lightwalletd, and Zebra endpoints.
The zkool CI workflow pins this repository's revision: update its
`MOCK_LEDGER_REV` to a published commit containing signing before running the
expanded test in CI.
