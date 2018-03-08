# Silme

A simple implementation of Blockchain writen in python, using silme you can generate new blocks (pow sha256) and create transactions, node is not implemented yet so the new transactions and blocks cant be broadcasted to other peers

## TODO

You can contribute to silme, simple open a pull request 

- [ ] Implement auth to rpc serer (user, password)
- [ ] Fix GetNextWorkRequired
- [ ] Implement p2p Networking(Node)

# INSTAL SILME
``` bash
git clone https://github.com/cvsae/silme
cd silme
sudo pip install -r silme_req.txt
./configure

```

# RUN SILME 
``` bash
cd silme
./silme-qt
```

# USAGE

## MINING

Start Mining using the start button in mining section, when you will find a vailid block you will credit the coinbase transaction value, to stop mining click the stop button in mining section, alternative for testing purposes you can use ./miner -d 1 to enable miining with debug results should be 
``` bash

[*] Working on block: 2
[*] Target: 110427836236357352041769395878404723568785424659630784333489133269811200
[*] Difficulty: 0
[*] Required hashes: 0
[*] Prev hash: 000009cb25c348b85b01819c52402adea224580263fbe9b915be8502c5220f82
```

## SEND COINS

Send coin section take 2 arguments, first to: the recipten pubkey and and second anount: the amount wich you want to sent to argument 1 pubkey


## Keys

``` python
CKey().MakeNewKey() # Generate a new private key 
CKey().GetPubKey(priv) # Get pubkey of the given private key 
CKey().GetAddress(pubkey) # Get address of the given pubkey

```

## Wallet

``` python
CWalletDB().WriteKey(key, pubkey) # Write a private key and their pubkey to wallet db
CWalletDB().IsMineKey(pubkey) # Return True if the give pubkey is in wallet
CWalletDB().GetMyAddresses() # Return a list of addresses from our wallet
CWalletDB().GetBalance() # Return wallet balance
CWalletDB().FindHash(amount) # Return a tx hash to use as input for a new transaction, tx hash must have the specified amount
CWalletDB().FindAddrFromHash(txhash) # Return the private key asociated with txhash
CWalletDB().GenerateTransaction(amount, recipten) # Generate a new transaction

```

## CBlockIndex

``` python
CBlockIndex() # Return info of the give blockhash or height
CBlockIndex(@HashOrHeight).Version() # Return @HashOrHeight version
CBlockIndex(@HashOrHeight).Prev() # Return @HashOrHeight previous block hash 
CBlockIndex(@HashOrHeight).Merkle() # Return @HashOrHeight merkle root 
CBlockIndex(@HashOrHeight).Time() # Return @HashOrHeight time 
CBlockIndex(@HashOrHeight).Bits() # Return @HashOrHeight bits 
CBlockIndex(@HashOrHeight).Nonce() # Return @HashOrHeight nonce 

```

## CTxIndex

``` python
CTxIndex() # Return info of the give transaction hash
CTxIndex(@tx_hash).Height() # Return the height of block of the give tx_hash
CTxIndex(@tx_hash).Version() # Return @tx_hash version 
CTxIndex(@tx_hash).Time() # Return @tx_hash time 
CTxIndex(@tx_hash).Value() # Return @tx_hash value
CTxIndex(@tx_hash).InputScript() # Return @tx_hash input_script 
CTxIndex(@tx_hash).OutputScript() # Return @tx_hash output_script 

```

## CBlockchainDB

``` python
CBlockchainDB() # Return info about blockchain
CBlockchainDB().getBestHeight() # Return the best height in the blockchain
CBlockchainDB().GetBestHash() # Return the best hash in the blockchain
CBlockchainDB().haveHash(@hash) # Return True if the give hash already exists False if not

```


