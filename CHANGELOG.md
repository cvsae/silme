# Changelog
All notable changes to this project will be documented in this file.

## Dev 0.0.3

- Store transactions signature
- Store blocks nonce
- Proccess new block received by peer, currently supports blocks only coinbase transactions.
- Add node


## Dev 0.0.2

- Added CBlockchain().GetTransactions() | Return all blockchain transaction
- Added Mempool().GetTransactions() | returns all mempool transactions
- Fix Memmpool().GetSize() | Return mempool size in bytes
- Added blocksize limit at 1MB
- Added log failrus in GenerateTransaction

## Dev 0.0.1

- Fix GetNextWorkRequired | Difficulty Changes every 6 blocks
- Fix Mempool | Include mempool transactions to new blocks
- New block validations | Check prev block | Check timestamp against prev | Check Proof Of Work
- Get balance of specifiec key
- Get Silme version via rpc
