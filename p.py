
import sqlite3


from os.path import expanduser
from termcolor import colored
from sys import platform
from construct import *
from bitcoin import *
import logging
import sqlite3
import string



class Sig(object):

    def SSign(self, tx, priv):
        sig = ecdsa_sign(str(tx),priv)
        return sig


    def VVerify(self, tx, signature, ous):
        return ecdsa_verify(str(tx),signature,ous)
        

    def VVVerify(self, msg, sig, pub):
        return ecdsa_verify(msg, sig, pub)



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


def GetAppDir():
    # currently suppports linux 
    if not platform == "linux":
        if not platform == "linux2":
            sys.exit(logg("Error: Unsupported platform"))
    return expanduser("~") + "/" + ".silme"


logging.basicConfig(level=logging.INFO, filename="debug.log", format='%(asctime)s %(message)s') # include timestamp


def logg(msg): logging.info(msg)


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

        # get all blockchain transactions
        conn = sqlite3.connect(GetAppDir() +  "/blockchain.db")
        conn.text_factory = str
        cur = conn.cursor() 
        cur.execute("SELECT * FROM transactions")
        txs = cur.fetchall()


        # calculate balance  

        for transaction in txs:
            pubkey = transaction[7].encode("hex_codec")[2:132]
            if self.IsMineKey(pubkey):
                balance += transaction[4]
                thisHash = transaction[5]
                # check if the hash have spend inputs 
                for ttx in txs:
                    if ttx[2] == thisHash:
                        # has spend coins
                        balance -= ttx[4]



        return balance / 100000000


    def FindHash(self, amount):
        # get all blockchain transactions
        conn = sqlite3.connect(GetAppDir() +  "/blockchain.db")
        conn.text_factory = str
        cur = conn.cursor() 
        cur.execute("SELECT * FROM transactions")
        txs = cur.fetchall()


        ntxs = []

        for transaction in txs:
            pubkey = transaction[7].encode("hex_codec")[2:132]
            if self.IsMineKey(pubkey):
                thisHash = transaction[5]
                if transaction[4] >= amount:
                    for ttx in txs:
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
            return "Not available balance to create this transaction"

        # collect hash
        thisHash = self.FindHash(amount)
        # privkey of the input hash 
        privv = self.FindAddrFromHash(thisHash)
        

        txNew = CTransaction()
        txNew.add("version", 1)
        txNew.add("prev_out", thisHash)
        txNew.add("time", int(time.time()))
        txNew.add("value", amount)
        txNew.input_script("hellolllllll")
        txNew.output_script(recipten)
        txNew.add("signature", Sig().SSign(str(txNew), privv))

        return txNew


# reserve a key to pay the coinbase 
privatekey = CKey().MakeNewKey()
publickey = CKey().GetPubKey(privatekey)




class CBlockchain(object):


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

        return Sig().VVerify(tx,signature, ous)
        



tx = CWalletDB().GenerateTransaction(40, publickey)


print CBlockchain().isVaildTx(tx)