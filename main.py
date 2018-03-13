#!/usr/bin/python
# Copyright (c) 2017 CVSC
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from binascii import hexlify, unhexlify
from binascii import b2a_hex, a2b_hex
from os.path import expanduser
from termcolor import colored
from sys import platform
from construct import *
from pybitcointools import *
import logging
import sqlite3
import socket
import string
import struct



# One silme can be split into 100000000 satoshi
COIN = 100000000
# Proof of Work limit 
bnProofOfWorkLimit = 0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
# Reward Per block
nCoin = 50
# Halving Every 210000 blocks
nSubsibyHalvingInterval = 210000
# MaxBlockSize
nMaxSize = 1000000 # 1MB



def GetAppDir():
    # currently suppports linux 
    if not platform == "linux":
        if not platform == "linux2":
            sys.exit(logg("Error: Unsupported platform"))
    return expanduser("~") + "/" + ".silme"


logging.basicConfig(level=logging.INFO, filename="debug.log", format='%(asctime)s %(message)s') # include timestamp


def logg(msg): logging.info(msg)



if not os.path.exists(GetAppDir()):
    # db isn't initalized, initialize it
    try:
        os.mkdir(GetAppDir())
    except Exception, e:
        raise
    else:
        logg("Initializing empty blockchain database at " + GetAppDir() + "/blockchain.db")
        blockchain_conn = sqlite3.connect(GetAppDir() + "/blockchain.db")
        blockchain_cursor = blockchain_conn.cursor()
        blockchain_cursor.execute("CREATE TABLE blocks (height INTEGER, hash, raw)")
        blockchain_cursor.execute("CREATE TABLE transactions (block, version, prev, time, value, hash, input_script, output_script)")
        blockchain_conn.commit()

        logg("Initializing empty wallet database at " + GetAppDir() + "/wallet.db")
        wallet_conn = sqlite3.connect(GetAppDir() + "/wallet.db")
        wallet_cursor = wallet_conn.cursor()
        wallet_cursor.execute("CREATE TABLE keys (private, pubkey)")
        wallet_cursor.execute("CREATE TABLE transactions (tx_hash)")
        wallet_conn.commit()

        logg("Initializing empty peers database at " + GetAppDir() + "/peers.db")
        peers_conn = sqlite3.connect(GetAppDir() + "/peers.db")
        peers_cursor = peers_conn.cursor()
        peers_cursor.execute("CREATE TABLE nodes (ip, port, status)")
        peers_conn.commit()


        # hardcode nodes
        peers_cursor.execute("INSERT INTO nodes VALUES (?,?,?)", ("127.0.0.1", 7777, "ok"))
        peers_cursor.execute("INSERT INTO nodes VALUES (?,?,?)", ("127.0.0.2", 7777, "ok"))
        peers_cursor.execute("INSERT INTO nodes VALUES (?,?,?)", ("127.0.0.3", 7777, "ok"))
        peers_cursor.execute("INSERT INTO nodes VALUES (?,?,?)", ("127.0.0.4", 7777, "ok"))
        peers_conn.commit()




        # add genesis to database 
        blockchain_cursor.execute("INSERT INTO blocks VALUES (?,?,?)", (1, "000009cb25c348b85b01819c52402adea224580263fbe9b915be8502c5220f82", "0100000000000000000000000000000000000000000000000000000000000000000000007a98ffba469fe652771c5bb7b236248b4d78e4127ef369f1b07e1071da069e2fba756b5affff0f1ef7830e00")) # Insert a row of data
        blockchain_conn.commit() 
        
        mempool_conn = sqlite3.connect(GetAppDir() + "/mempool.db")
        mempool_cursor = mempool_conn.cursor()
        mempool_cursor.execute("CREATE TABLE transactions (version, prev, time, value, hash, input_script, output_script, signature)")
        mempool_conn.commit()

    
def internetConnection(host="8.8.8.8", port=53, timeout=3):
    
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except Exception as ex:
        return False



def haveReachableNode():

    have = 0 
    
    peers_conn = sqlite3.connect(GetAppDir() + "/peers.db")
    peers_cursor = peers_conn.cursor()
    peers = peers_cursor.execute("SELECT * FROM nodes").fetchall()

    for peer in peers:
        peerip = peer[0]
        peerport = peer[1]
        peerstat = peer[2]

        s = socket.socket()

        try:
            s.connect(peerip, port)
        except:
            s.close()
        else:
            have +=1
    if have > 0:
        return True
    return False





class CKey(object):

    # CKey class use https://github.com/vbuterin/pybitcointools
    # from bitcoin import *

    def MakeNewKey(self):
        rand_str = lambda n: ''.join([random.choice(string.lowercase) for i in xrange(n)])
        return sha256(rand_str(10))


    def GetPubKey(self, priv):
        return privtopub(priv)



    def GetAddress(self, pub):
        return pubtoaddr(pub)




class Sig(object):

    def SSign(self, tx, priv):
        sig = ecdsa_sign(str(tx),priv)
        return sig


    def VVerify(self, tx, signature):
        return ecdsa_verify(str(tx),signature,tx["output_script"].encode("hex_codec")[2:132])
        

    def VVVerify(self, msg, sig, pub):
        return ecdsa_verify(msg, sig, pub)



class CBlockchain(object):


    def GetTransactions(self):
        # get all blockchain transactions
        conn = sqlite3.connect(GetAppDir() +  "/blockchain.db")
        conn.text_factory = str
        cur = conn.cursor() 
        cur.execute("SELECT * FROM transactions")
        return cur.fetchall()


    def isVaildTx(self, tx):
        
        amount = tx["value"]
        inHash = tx["prev_out"]
        itime = tx["time"]
        # store signature in memory
        signature = tx["signature"]
        # remove signature from tx 
        del tx['signature']



        conn = sqlite3.connect(GetAppDir() +  "/blockchain.db")
        conn.text_factory = str
        cur = conn.cursor() 
        res = cur.execute("SELECT value FROM transactions where hash = ?", (inHash,)).fetchone()[0]
        ous = cur.execute("SELECT output_script FROM transactions where hash = ?", (inHash,)).fetchone()[0].encode("hex_codec")[2:132]


        if not res:
            return False

        if res < amount:
            return False

        if itime > int(time.time()):
            return False

        return ecdsa_verify(str(tx),signature,ous)



class CWalletDB(object):


    def __init__(self):
        self.conn = sqlite3.connect(GetAppDir() + "/wallet.db")
        self.conn.text_factory = str
        self.cur = self.conn.cursor() 



    def WriteKey(self, key, pubkey):
        try:
            self.cur.execute("INSERT INTO keys VALUES (?,?)", (key, pubkey))
            self.conn.commit()
            return True
        except Exception, e:
            return False 


    def IsMineKey(self, pubkey):
        self.cur.execute("SELECT pubkey from keys")
        results = self.cur.fetchall()
        return pubkey in str(results)



    def GetMyAddresses(self):
        self.cur.execute("SELECT private from keys")
        results = self.cur.fetchall()

        addresses = []
        
        for priv in results:
            addresses.append(CKey().GetAddress(str(priv)))

        return addresses


    def GetBalance(self):

        balance = 0 

        # calculate balance  
        for transaction in CBlockchain().GetTransactions():
            pubkey = transaction[7].encode("hex_codec")[2:132]
            if self.IsMineKey(pubkey):
                balance += transaction[4]
                thisHash = transaction[5]
                # check if the hash have spend inputs 
                for ttx in CBlockchain().GetTransactions():
                    if ttx[2] == thisHash:
                        # has spend coins
                        balance -= ttx[4] * COIN
    
        return float(balance / COIN)


    def FindHash(self, amount):

        ntxs = []

        for transaction in CBlockchain().GetTransactions():
            pubkey = transaction[7].encode("hex_codec")[2:132]
            if self.IsMineKey(pubkey):
                thisHash = transaction[5]
                if transaction[4] >= amount:
                    for ttx in CBlockchain().GetTransactions():
                        if type(ttx[2] == int):
                            return thisHash


    def FindAddrFromHash(self, txhash):
        # get all blockchain transactions
        conn = sqlite3.connect(GetAppDir() +  "/blockchain.db")
        conn.text_factory = str
        cur = conn.cursor() 
        res = cur.execute("SELECT output_script FROM transactions where hash = ?", (txhash,)).fetchone()[0]
        pubkey = res.encode("hex_codec")[2:132]
        thisPriv = self.cur.execute("SELECT private FROM keys where pubkey = ?", (pubkey,)).fetchone()[0]
        return thisPriv




    def GenerateTransaction(self, amount, recipten):
        mybalance = self.GetBalance()


        if mybalance < amount:
            # not enought balance to create this transaction
            logg("GenerateTransaction() Failed not enought balance to create this transaction")
            return False

        if len(recipten) != 130:
            # not vaild recipten key
            logg("GenerateTransaction() Failed not vaild recipten key")
            return False
            
        # collect hash
        thisHash = self.FindHash(amount)
        # privkey of the input hash 
        priv = self.FindAddrFromHash(thisHash)
        
        txNew = CTransaction()
        txNew.add("version", 1)
        txNew.add("prev_out", thisHash)
        txNew.add("time", int(time.time()))
        txNew.add("value", amount)
        txNew.input_script("SilmeTransaction")
        txNew.output_script(recipten)
        txNew.add("signature", Sig().SSign(str(txNew), priv))
        if Mempool().addtx(txNew):
            return True
        return False







class Mempool(object):


    def __init__(self):
        # initilize empty mempool
        self.mem_conn = sqlite3.connect(GetAppDir() + "/mempool.db")
        self.mem_conn.text_factory = str
        self.mem_cur = self.mem_conn.cursor()
        



    def HaveHash(self, tx):
        # calculate transaction hash
        thisHash = hashlib.sha256(hashlib.sha256(str(tx)).hexdigest()).hexdigest()
        # check if tx already in mempool
        mempool_txs = self.mem_cur.execute("SELECT * FROM transactions").fetchall()
        return thisHash in mempool_txs



    def addtx(self, tx):
        # add tx to mem pool
        
        if not self.HaveHash(tx):
            self.mem_cur.execute("INSERT INTO transactions VALUES (?,?,?,?,?,?,?, ?)", (tx["version"], tx["prev_out"], tx["time"], tx["value"], hashlib.sha256(hashlib.sha256(str(tx)).hexdigest()).hexdigest(), tx["input_script"], tx["output_script"], tx["signature"])) # Insert a row of data
            self.mem_conn.commit()
            logg("Mempool() : Transaction %s added to mempool" %(hashlib.sha256(hashlib.sha256(str(tx)).hexdigest()).hexdigest(),))
            return True
        logg("Mempool() : Transaction %s already to mempool" %(hashlib.sha256(hashlib.sha256(str(tx)).hexdigest()).hexdigest(),))
        return False, "Already have"
        

    def CountTxs(self):
        # get transaction lenght
        mempool_txs = self.mem_cur.execute("SELECT * FROM transactions").fetchall()
        return len(mempool_txs)



    def GetTransactions(self):
        # get all mempool transactions
        self.mem_cur.execute("SELECT * FROM transactions")
        return self.mem_cur.fetchall()



    def GetSize(self):
        fsize = 0 
        mempool_txs = self.mem_cur.execute("SELECT * FROM transactions").fetchall()
        for tx in mempool_txs:
            ff += sys.getsizeof(tx)
        return fsize

    def gettx(self, n):
        return self.mem_cur.execute("SELECT * FROM transactions").fetchall()[n]


    def RemoveTx(self, tx):

        query = 'delete from transactions where hash=?'
        self.mem_cur.execute(query, (tx.strip(),))
        self.mem_conn.commit()




    

def decode_uint32(self):
        return struct.unpack("<I", self)[0]


def format_hash(hash_):
    return str(hexlify(hash_[::-1]).decode("utf-8"))






class CBlockIndex(object):
    # ThisBlock 
    def __init__(self, obj):
        self.conn = sqlite3.connect(GetAppDir() + "/blockchain.db")
        self.conn.text_factory = str
        self.cur = self.conn.cursor() 
        self.block = obj
        
        if type(self.block) == int:
            self.hash = self.cur.execute("SELECT hash FROM blocks WHERE height = ?", (self.block,)).fetchone()[0]
            self.raw = self.cur.execute("SELECT raw FROM blocks WHERE height = ?", (self.block,)).fetchone()[0]
            self.ntxs = self.cur.execute("SELECT COUNT(*) FROM transactions where block = ?", (self.block,)).fetchone()[0]
            self.transactions = self.cur.execute("SELECT * FROM transactions where block = ?", (self.block,)).fetchall()

        else:
            self.height = self.cur.execute("SELECT height FROM blocks WHERE hash = ?", (self.block,)).fetchone()[0]
            self.raw = self.cur.execute("SELECT raw FROM blocks WHERE hash = ?", (self.block,)).fetchone()[0]
            self.ntxs = self.cur.execute("SELECT COUNT(*) FROM transactions where block = ?", (self.height,)).fetchone()[0]
            self.transactions = self.cur.execute("SELECT * FROM transactions where block = ?", (self.height,)).fetchall()

    
    

    def Height(self):
        # get height 
        return self.height


    def Raw(self):
        # get raw block 
        return self.raw


    def Version(self):
        # get version 
        return decode_uint32(a2b_hex(self.raw[:8]))


    def Prev(self):
        # get prev hash 
        return self.raw[8:72]


    def Merkle(self):
        # get merkle root 
        return format_hash(a2b_hex(self.raw[72:136]))


    def Time(self):
        # get time 
        return decode_uint32(a2b_hex(self.raw[136:144]))


    def Bits(self):
        # get bits 
        return decode_uint32(a2b_hex(self.raw[144:152]))


    def Nonce(self):
        # get nonce 
        return decode_uint32(a2b_hex(self.raw[152:160]))


        
class CTxIndex(object):
    # ThisTx
    def __init__(self, obj):
        self.conn = sqlite3.connect((GetAppDir() + "/blockchain.db"))
        self.cur = self.conn.cursor() 
        self.tx = obj


    def Height(self):
        self.cur.execute("SELECT height FROM transactions WHERE hash = ?", (self.tx,))
        result = self.cur.fetchone()
        return result[0]


    def Version(self):
        self.cur.execute("SELECT version FROM transactions WHERE hash = ?", (self.tx,))
        result = self.cur.fetchone()
        return result[0]


    def Time(self):
        self.cur.execute("SELECT time FROM transactions WHERE hash = ?", (self.tx,))
        result = self.cur.fetchone()
        return result[0]


    def Value(self):
        self.cur.execute("SELECT value FROM transactions WHERE hash = ?", (self.tx,))
        result = self.cur.fetchone()
        return result[0]


    def InputScript(self):
        self.cur.execute("SELECT input_script FROM transactions WHERE hash = ?", (self.tx,))
        result = self.cur.fetchone()
        return result[0]


    def OutputScript(self):
        self.cur.execute("SELECT output_script FROM transactions WHERE hash = ?", (self.tx,))
        result = self.cur.fetchone()
        return result[0]





class CTransaction(dict):

    def __init__(self):
        self = dict()
        self.clear()

    def input_script(self, message):
        psz_prefix = ""
        #use OP_PUSHDATA1 if required
        if len(message) > 76: psz_prefix = '4c'
        script_prefix = '04ffff001d0104' + psz_prefix + chr(len(message)).encode('hex')
        input_script_f  = (script_prefix + message.encode('hex')).decode('hex')
        self.add("input_script", input_script_f)

    def output_script(self, pubkey):
        script_len = '41'
        OP_CHECKSIG = 'ac'
        output_script_f = (script_len + pubkey + OP_CHECKSIG).decode('hex')
        self.add("output_script", output_script_f)


    def add(self, key, value):
        self[key] = value




    def clear(self):
        # clear the dict 
        self.clear()



    def getHash(self):
        # transaction hash 
        return hashlib.sha256(hashlib.sha256(str(self)).digest()).digest()






class CBlockchainDB(object):


    def __init__(self):
        self.conn = sqlite3.connect((GetAppDir() + "/blockchain.db"))
        self.conn.text_factory = str
        self.cur = self.conn.cursor() 


    def getBestHeight(self):
        self.cur.execute("SELECT height from blocks")
        results = self.cur.fetchall()
        return len(results)




    def GetBestHash(self):
        self.cur.execute('SELECT hash FROM blocks')
        results = self.cur.fetchall()
        return results[len(results) -1][0]



    def haveHash(self, hash):
        self.cur.execute("SELECT hash FROM blocks WHERE hash = ?", (hash,))
        result = self.cur.fetchone()
        if result:
            return True
        return False


    def insertTxs(self, height, pblock):
        conn = sqlite3.connect((GetAppDir() + "/blockchain.db"))
        conn.text_factory = str
        ntx = len(pblock.vtx)
        height = self.getBestHeight()

        try:
            for x in xrange(0,ntx):
                cursor = conn.cursor()
                txhash = hashlib.sha256(hashlib.sha256(str(pblock.vtx[x])).hexdigest()).hexdigest()
                cursor.execute("INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?)", (height, pblock.vtx[x]["version"],pblock.vtx[x]["prev_out"],pblock.vtx[x]["time"], pblock.vtx[x]["value"], txhash, pblock.vtx[x]["input_script"], pblock.vtx[x]["output_script"])) # Insert a row of data
                conn.commit()
        except Exception, e:
            logg(e)
            return False 


    def insertBlock(self, pblock, block):

        b_height = self.getBestHeight() + 1 

        b_hash = hashlib.sha256(hashlib.sha256(block).digest()).digest()[::-1].encode('hex_codec')

           
        try:
            self.cur.execute("INSERT INTO blocks VALUES (?,?,?)", (b_height, b_hash, block))
            self.conn.commit()
            self.insertTxs(b_height, pblock)
        except Exception, e:
            logg(e)
            return False 
        else:
            return True






class CBlock(object):

    # block header
    nVersion = None       # version 
    hashPrevBlock = None  # previous block hash 
    hashMerkleRoot = None # merkle 
    nTime = None          # time 
    nBits = None          # bits 
    nNonce = None         # nonce

    vtx = []
    vMerkleTree = []


    def CBlock(self):
        SetNull()



    def SetNull(self):
        self.nVersion = 1
        self.hashPrevBlock = 0
        self.hashMerkleRoot = 0
        self.nTime = 0
        self.nBits = 0
        self.nNonce = 0
        del self.vtx[:]
        del self.vMerkleTree[:]


    def IsNull(self):
        return self.nBits == 0




    def Nullvtx(self):
        del self.vtx[:]




    def hash2(self, a, b):
        # Reverse inputs before and after hashing
        # due to big-endian / little-endian nonsense
        a1 = a.decode('hex')[::-1]
        b1 = b.decode('hex')[::-1]
        h = hashlib.sha256(hashlib.sha256(a1+b1).digest()).digest()
        return h[::-1].encode('hex')




    def BuildMerkleTree(self):
        del self.vMerkleTree[:]

        if len(self.vtx) == 1:
            merkle = hashlib.sha256(hashlib.sha256(str(self.vtx[0])).digest()).digest()[::-1]
            return merkle
            newtxHashes = []
            # Process pairs. For odd length, the last is skipped
            for i in range(0, len(txHashes)-1, 2):
                newtxHashes.append(self.hash2(self.vtx[i], txHashes[i+1]))
            if len(txHashes) % 2 == 1:
                newtxHashes.append(self.hash2(self.vtx[-1], txHashes[-1]))
            return BuildMerkleTree(newtxHashes)



    def pprint(self):
        print("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s)\n") %("missinghash", self.hashPrevBlock,self.nVersion, self.hashMerkleRoot)





class tmp():
    
    nVersion = None 
    hashPrevBlock = None
    hashMerkleRoot = None 
    nTime = None 
    nBits = None 
    nNonce = None 

    def hex_to_hash(self, h):
        return b''.join((unhexlify(h)))

    def build(self):
        block_header = Struct("block_header",
          Bytes("version",4),
          Bytes("hash_prev_block", 32),
          Bytes("hash_merkle_root", 32),
          Bytes("time", 4),
          Bytes("bits", 4),
          Bytes("nonce", 4))

        Cblock = block_header.parse('\x00'*80)
        Cblock.version          = struct.pack('<I', 1)
        Cblock.hash_prev_block  = struct.pack('>32s', self.hex_to_hash(self.hashPrevBlock))
        Cblock.hash_merkle_root = struct.pack('>32s', str(self.hashMerkleRoot))
        Cblock.time             = struct.pack('<I', self.nTime)
        Cblock.bits             = struct.pack('<I', self.nBits)
        Cblock.nonce            = struct.pack('<I', self.nNonce)
        return block_header.build(Cblock)






class Proccess(object):


    def thisBlock(self, block, pblock, nonce):
        logg("Proccessing new block\n")
        # calculate hash 
        block_hash = hashlib.sha256(hashlib.sha256(block).digest()).digest()[::-1].encode('hex_codec')



        
        # Check for duplicate
        if CBlockchainDB().haveHash(block_hash):
            logg("ProcessBlock() : already have block %s %s" %(CBlockIndex(block_hash).getHeight(), block_hash,))
            return False 
        
        # Check prev block
        if CBlockchainDB().GetBestHash() != block[8:72]:
            logg("CheckBlock() : prev block not found")
            return False

        # Check timestamp against prev
        if CBlockIndex(CBlockchainDB().GetBestHash()).Time() >= decode_uint32(a2b_hex(block[136:144])):
            logg("CheckBlock() : block's timestamp is too early")
            return False


        # Check Proof Of Work
        if decode_uint32(a2b_hex(block[144:152])) != GetNextWorkRequired():
            logg("CheckBlock() : incorrect proof of work")
            return False

        # Check size 
        if sys.getsizeof(pblock.vtx) > nMaxSize:
            logg("CheckBlock() : Block size failed")
            return False


        # Preliminary checks
        if self.CheckBlock(block, pblock, nonce):
            return True 


    def CheckBlock(self, block, pblock, nonce):

        # be sure that first tx is coinbase
        if not pblock.vtx[0]["prev_out"] == 0:
            logg("CheckBlock() : first tx is not coinbase")
            return False

        # be sure that only 1 coinbase tx included 
        for x in xrange(1,len(pblock.vtx)):
            if pblock.vtx[x]["prev_out"] == 0:
                logg("CheckBlock() : more than one coinbase")
                return False
        
        # check transactions, not include coinbase tx 
        for x in xrange(1,len(pblock.vtx)):
            if not self.thisTxIsVaild(pblock.vtx[x]):
                logg("CheckBlock() : Invaild tx found")
                return False
        

        # verify input sig
        for x in xrange(1,len(pblock.vtx)):
            if not CBlockchain().isVaildTx(pblock.vtx[x]):
                logg("CheckBlock() : Failed to verify input sig")
                return False

        return True




    def thisTxIsPayingMe(self, tx):
        # get this tx out pubkey 
        tx_pubkey = tx["output_script"].encode("hex_codec")[2:132]
        return CWalletDB().IsMineKey(tx_pubkey)





    def thisTxIsVaild(self, tx):

        # check transaction verification

        # store signature in memory
        signature = tx["signature"]
        # remove signature from tx 
        del tx['signature']
        # do verify 
        try:
            Sig().VVerify(tx,signature)
            tx['signature'] = signature
        except Exception, e:
            tx['signature'] = signature
            logg("Transaction %s verification error" %hashlib.sha256(hashlib.sha256(str(tx)).digest()).digest().encode("hex_codec"))
            logg(e)
            return False


        
        # check for empty scripts 
        if len(tx["input_script"]) < 10 or len(tx["output_script"]) < 10:
            logg("Proccess::thisTxIsVaild() : vin or vout empty")
            return False
        
        # check for negative tx value
        if tx["value"] == 0:
            logg("Proccess::thisTxIsVaild() : txout.nValue negative")
            return False
        
        # check for missing prevout 
        if tx["prev_out"] == 0:
            logg("Proccess::thisTxIsVaild() : prevout is null")
            return False




        return True




def GetBlockValue(height, fees):
    subsidy = nCoin * COIN
    subsidy >>= (height / nSubsibyHalvingInterval)
    return subsidy + fees



def GetBalance(pub):
    # get balance of specifiec key

    # balance
    balance = 0 

    # get all blockchain transactions
    txs = CBlockchain().GetTransactions()

    # calculate balance  
    for transaction in txs:
        pubkey = transaction[7].encode("hex_codec")[2:132]

        if pub == pubkey:
            balance += transaction[4]
            thisHash = transaction[5]
            # check if the hash have spend inputs 
            for ttx in txs:
                if ttx[2] == thisHash:
                    balance -= ttx[4] * COIN
    return balance 



######## Keys 


def AddKey(pkey):
    key = CKey()
    pubkey = key.GetPubKey(pkey)
    return CWalletDB().WriteKey(pkey, pubkey)





def GenerateNewKey():
    key = CKey()
    pkey = key.MakeNewKey()

    if not AddKey(pkey):
        sys.exit(logg("GenerateNewKey() : AddKey failed\n"))
    return key.GetPubKey(pkey)


   
   
def GetNextWorkRequired():

    # latest block hash 
    pindexLast = CBlockchainDB().GetBestHash()
    
    # Difficulty will change every 600 seconds or 10 minuntes
    nTargetTimespan = 600 
    # We need a new block every 100 seconds
    nTargetSpacing = 100
    # That give us a interval 6 blocks
    nInterval = nTargetTimespan / nTargetSpacing
    
    
    # if the last block height == 1 return the minimun diif
    if CBlockIndex(pindexLast).Height() == 1:
        return 0x1e0fffff


    # Only change once per interval
    if ((CBlockIndex(pindexLast).Height()+1) % nInterval != 0):
        # Return the last block bits (difficulty)
        return CBlockIndex(pindexLast).Bits()


    # Go back by what we want to be 10 minuntes worth of blocks
    # nActualTimespan is the avg time of the last 6 blocks, example if each of the last 6 blocks took 30 seconds nActualTimespan will be 180
    nActualTimespan = CBlockIndex(pindexLast).Time() - CBlockIndex(CBlockIndex(pindexLast).Height() - nInterval + 2).Time()
    # so if the nActualTimespan is bigger the nTargetTimespan means that blocks are mined slowly, difficulty will be reduced,
    # if the nActualTimespan is lower than nTargetTimespan means that blocks are mined quick, difficulty will be increased

    logg("nActualTimespan = %d  before bounds\n" %nActualTimespan)

    if nActualTimespan < nTargetTimespan/4:
        nActualTimespan = nTargetTimespan/4
    if nActualTimespan > nTargetTimespan*4:
        nActualTimespan = nTargetTimespan*4

    bnNew = bits2target(CBlockIndex(pindexLast).Bits())
    bnNew *= nActualTimespan
    bnNew /= nTargetTimespan

    if bnNew > bnProofOfWorkLimit:
        bnNew = bnProofOfWorkLimit

    

    logg("\n\n\nGetNextWorkRequired RETARGET *****\n")
    logg("nTargetTimespan = %d    nActualTimespan = %d\n" %(nTargetTimespan, nActualTimespan,))
    logg("Last %d blocks time average was %d\n" %(nInterval, nActualTimespan,))
    logg("Before: %08x  %s\n" %(CBlockIndex(pindexLast).Bits(), nActualTimespan,))
    logg("After:  %08x  %s\n" %(GetCompact(int(bnNew)), nActualTimespan,))

    return target2bits(bnNew)




def target2bits(target):
        MM = 256*256*256
        c = ("%064X"%int(target))[2:]
        i = 31
        while c[0:2]=="00":
            c = c[2:]
            i -= 1
        c = int('0x'+c[0:6],16)
        if c >= 0x800000:
            c //= 256
            i += 1
        new_bits = c + MM * i
        return new_bits


def num2mpi(n):
        """convert number to MPI string"""
        if n == 0:
                return struct.pack(">I", 0)
        r = ""
        neg_flag = bool(n < 0)
        n = abs(n)
        while n:
                r = chr(n & 0xFF) + r
                n >>= 8
        if ord(r[0]) & 0x80:
                r = chr(0) + r
        if neg_flag:
                r = chr(ord(r[0]) | 0x80) + r[1:]
        datasize = len(r)
        return struct.pack(">I", datasize) + r



def GetCompact(n):
        """convert number to bc compact uint"""
        mpi = num2mpi(n)
        nSize = len(mpi) - 4
        nCompact = (nSize & 0xFF) << 24
        if nSize >= 1:
                nCompact |= (ord(mpi[4]) << 16)
        if nSize >= 2:
                nCompact |= (ord(mpi[5]) << 8)
        if nSize >= 3:
                nCompact |= (ord(mpi[6]) << 0)

        return nCompact







   
def bits2target(bits):
    """ Convert bits to target """
    exponent = ((bits >> 24) & 0xff)
    mantissa = bits & 0x7fffff
    if (bits & 0x800000) > 0:
        mantissa *= -1 
    return (mantissa * (256**(exponent-3)))


   

def CalculateDiff():
    """ Calculate current difficulty """
    # diff is minimun difficulty target / current_target 
    p = bits2target(0x1d00ffff)
    y = bits2target(GetNextWorkRequired())
    return p / y


def NetworkHashrate():
    # network hashrate in ghs
    difficulty = CalculateDiff()
    return difficulty * 2**32 / 100 / 1000000000

   

def HashesTowin():
    """ Calculate required hashes to find a block """
    return CalculateDiff() * 2**256 / (0xffff * 2**208)





def generate_hashes_from_block(data_block):
    sha256_hash = hashlib.sha256(hashlib.sha256(data_block).digest()).digest()[::-1]
    return sha256_hash, sha256_hash




def generate_hash(data_block, targetx):
    nonce           = 0
    target = targetx
    last_updated = time.time()

    while True:
        sha256_hash, header_hash = generate_hashes_from_block(data_block)
        if int(header_hash.encode('hex_codec'), 16) < target:
            return (sha256_hash, nonce, data_block)
        else:
            nonce      +=1
            data_block = data_block[0:len(data_block) - 4] + struct.pack('<I', nonce)  

