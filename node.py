#!/usr/bin/python
# Original Author : https://github.com/benediktkr at /ncpoc
# Modified by CVSC

from main import *
import messages
import cryptotools
import select
from datetime import datetime
from time import time
from functools import partial
import version

from twisted.internet.endpoints import TCP4ServerEndpoint, TCP4ClientEndpoint
from twisted.internet.error import CannotListenError
from twisted.internet import reactor
from twisted.internet.protocol import Protocol, Factory
from twisted.internet.endpoints import connectProtocol
from twisted.internet.task import LoopingCall

PING_INTERVAL = 1200.0 # 20 min = 1200.0
BOOTSTRAP_NODES = ["localhost:3456",
                   "localhost:5004",
                   "localhost:5007",
                   "localhost:5005"]

def _print(*args):
    time = datetime.now().time().isoformat()[:8]
    print time,
    print " ".join(map(str, args))

class NCProtocol(Protocol):
    def __init__(self, factory, state="GETHELLO", kind="LISTENER"):
        self.factory = factory
        self.state = state
        self.VERSION = 1
        self.remote_nodeid = None
        self.kind = kind
        self.nodeid = self.factory.nodeid
        self.protoversion = version._protocol_version
        self.lc_ping = LoopingCall(self.send_PING)
        self.message = partial(messages.envelope_decorator, self.nodeid)

        self.conn = sqlite3.connect(GetAppDir() +  "/blockchain.db")
        self.conn.text_factory = str
        self.cur = self.conn.cursor() 

    def connectionMade(self):
        r_ip = self.transport.getPeer()
        h_ip = self.transport.getHost()
        self.remote_ip = r_ip.host + ":" + str(r_ip.port)
        self.host_ip = h_ip.host + ":" + str(h_ip.port)

    def print_peers(self):
        if len(self.factory.peers) == 0:
            _print(" [!] PEERS: No peers connected.")
        else:
            _print(" [ ] PEERS:")
            for peer in self.factory.peers:
                addr, kind = self.factory.peers[peer][:2]
                _print("     [*]", peer, "at", addr, kind)

    def write(self, line):
        self.transport.write(line + "\n")

    def connectionLost(self, reason):
        # NOTE: It looks like the NCProtocol instance will linger in memory
        # since ping keeps going if we don't .stop() it.
        try: self.lc_ping.stop()
        except AssertionError: pass

        try:
            self.factory.peers.pop(self.remote_nodeid)
            if self.nodeid != self.remote_nodeid:
                self.print_peers()
        except KeyError:
            if self.nodeid != self.remote_nodeid:
                _print(" [ ] GHOST LEAVES: from", self.remote_nodeid, self.remote_ip)

    def dataReceived(self, data):
        for line in data.splitlines():
            line = line.strip()
            envelope = messages.read_envelope(line)


            if self.state in ["GETHELLO", "SENTHELLO"]:
                # Force first message to be HELLO or crash
                if envelope['msgtype'] == 'hello':
                    self.handle_HELLO(line)
                else:
                    _print(" [!] Ignoring", envelope['msgtype'], "in", self.state)
            
            if envelope['msgtype'] == 'ping':
                self.handle_PING(line)
            elif envelope['msgtype'] == 'pong':
                self.handle_PONG(line)
            elif envelope['msgtype'] == 'addr':
                 self.handle_ADDR(line)
            elif envelope["msgtype"] == "ask_needsync":
                self.handle_SyncNeed(line)
            elif envelope['msgtype'] == "getblocks":
                self.handle_sendBlocks(line)
            elif envelope["msgtype"] == "needsync":
                self.handle_Sync(line)
            elif envelope["msgtype"] == "getblock":
                self.handle_ReceivedBlock(line)
            elif envelope["msgtype"] == "a_mempool":
                self.SendMempool()
            elif envelope["msgtype"] == "s_memppol":
                self.Handle_Mempool(line)



    def SendMempool(self):
        logg("Sending memppol transactions to %s" %self.remoteip)
        mempool_txs = Mempool().GetTransactions()
        message = create_send_mempool(self.nodeid, mempool_txs)
        self.write(message)


    def Handle_Mempool(self, data):
        logg("Received mempool transactions from %s" %self.remoteip)
        for line in data.splitlines():
            line = line.strip()
            envelope = messages.read_envelope(line)
            transactions = envelope["data"]["transactions"]
            Mempool().gotMempool(transactions)






    def handle_Sync(self, data):
        envelope = messages.read_envelope(data)
        # ask if we need sync
        if envelope["data"]["need"]:
            msg = messages.create_getblocks(self.nodeid, CBlockchainDB().getBestHeight())
            logg("We need sync, we are %d block back")
            self.write(msg)




    def handle_ReceivedBlock(self, data):
        logg("Received new block from %s " %self.remote_nodeid)
        for line in data.splitlines():
            line = line.strip()
            envelope = messages.read_envelope(line)

        thisRaw = envelope["data"]["raw"]
        thisCoinbase = envelope["data"]["coinbase"]
        thisTransactions = envelope["data"]["transactions"]
        thisNonce = envelope["data"]["b_nonce"]
        
        if thisBlock(self.remote_ip, thisRaw, thisCoinbase, thisTransactions, thisNonce).isVaild():
            logg("Received block from %s is vaild" %self.remote_ip)
        else:
            logg("Received block from %s rejected" %self.remote_ip)





    def handle_SyncNeed(self, data):
        envelope = messages.read_envelope(data)
        if envelope['msgtype'] == "ask_needsync":
           # handle client messages wich ask us if he needs sync
           # Client Bestheight
           thisHeight = envelope["data"]["height"]
           # Client Besthash
           thisHash = envelope["data"]["hash"]
           # check if our besthash height is > than client height
           if CBlockIndex(CBlockchainDB().GetBestHash()).Height() > thisHeight:
              # client is back
              isBack = CBlockIndex(CBlockchainDB().GetBestHash()).Height() -thisHeight
              # create a message, included our nodeid, our best height, and the diffrence
              message = messages.create_reply_need_sync(self.nodeid, CBlockIndex(CBlockchainDB().GetBestHash()).Height(), isBack)
              self.write(message)


    def handle_sendBlocks(self,  data):
            # handle client messages wich ask us to send it blocks
            # Client Bestheight
            envelope = messages.read_envelope(data)
            thisHeight = envelope["data"]["height"]

            print "start synced"

            if CBlockIndex(CBlockchainDB().GetBestHash()).Height() > thisHeight:
               # client is back
               isBack = CBlockIndex(CBlockchainDB().GetBestHash()).Height() -thisHeight
               # get all blocks from db where their height is > client height
               blocks = self.cur.execute("SELECT * FROM blocks where height > ?", (thisHeight,)).fetchall()
               for block in blocks:
                   thisHeight = block[0]
                   thisRaw = block[2]
                   thisNonce = block[3]
                   thisCoinbase = self.cur.execute("SELECT * FROM transactions where block = ?", (thisHeight,)).fetchone()
                   thisTransactions = self.cur.execute("SELECT * FROM transactions where block = ?", (thisHeight,)).fetchall()
                   message = messages.getblock(self.nodeid, thisRaw, thisCoinbase, thisTransactions, thisNonce)
                   self.write(message)


    def send_PING(self):
        _print(" [>] PING   to", self.remote_nodeid, "at", self.remote_ip)
        ping = messages.create_ping(self.nodeid)
        self.write(ping)



    def handle_PING(self, ping):
        if messages.read_message(ping):
            pong = messages.create_pong(self.nodeid)
            self.write(pong)



    def send_ADDR(self):
        _print(" [>] Telling " + self.remote_nodeid + " about my peers")
        # Shouldn't this be a list and not a dict?
        peers = self.factory.peers
        listeners = [(n, peers[n][0], peers[n][1], peers[n][2])
                     for n in peers]
        addr = messages.create_addr(self.nodeid, listeners)
        self.write(addr)



    def handle_ADDR(self, addr):
        try:
            nodes = messages.read_message(addr)['nodes']
            _print(" [<] Recieved addr list from peer " + self.remote_nodeid)
            #for node in filter(lambda n: nodes[n][1] == "SEND", nodes):
            for node in nodes:
                _print("     [*] "  + node[0] + " " + node[1])
                if node[0] == self.nodeid:
                    return
                if node[1] != "SPEAKER":
                    _print(" [ ] Not connecting to " + node[0] + ": is " + node[1])
                    return
                if node[0] in self.factory.peers:
                    _print(" [ ] Not connecting to " + node[0]  + ": already connected")
                    return
                _print(" [ ] Trying to connect to peer " + node[0] + " " + node[1])
                # TODO: Use [2] and a time limit to not connect to "old" peers
                host, port = node[0].split(":")
                point = TCP4ClientEndpoint(reactor, host, int(port))
                d = connectProtocol(point, NCProtocol(ncfactory, "SENDHELLO", "SPEAKER"))
                d.addCallback(gotProtocol)
        except messages.InvalidSignatureError:
            print addr
            _print(" [!] ERROR: Invalid addr sign ", self.remote_ip)
            self.transport.loseConnection()

    def handle_PONG(self, pong):
        pong = messages.read_message(pong)
        _print(" [<] PONG from", self.remote_nodeid, "at", self.remote_ip)
        # hacky
        addr, kind = self.factory.peers[self.remote_nodeid][:2]
        self.factory.peers[self.remote_nodeid] = (addr, kind, time())



    def send_HELLO(self):
        hello = messages.create_hello(self.nodeid, self.VERSION)
        self.transport.write(hello + "\n")
        self.state = "SENTHELLO"



    def handle_HELLO(self, hello):
        try:
            hello = messages.read_message(hello)
            self.remote_nodeid = hello['nodeid']
            protoversion = hello["protocol"]

            if self.remote_nodeid == self.nodeid:
                _print(" [!] Found myself at", self.host_ip)
                self.transport.loseConnection()
            else:
                if self.state == "GETHELLO":
                    my_hello = messages.create_hello(self.nodeid, self.VERSION, self.protoversion)
                    self.transport.write(my_hello + "\n")
                self.add_peer(protoversion)
                self.state = "READY"
                self.print_peers()
                self.askSync()
                #self.write(messages.create_ping(self.nodeid))
                if self.kind == "LISTENER":
                    # The listener pings it's audience
                    _print(" [ ] Starting pinger to " + self.remote_nodeid)
                    self.lc_ping.start(PING_INTERVAL, now=False)
                    # Tell new audience about my peers
                    self.send_ADDR()
        except messages.InvalidSignatureError:
            _print(" [!] ERROR: Invalid hello sign ", self.remoteip)
            self.transport.loseConnection()

    def askSync(self):
        msg = messages.create_ask_need_sync(self.nodeid, CBlockchainDB().GetBestHash(), CBlockchainDB().getBestHeight())
        self.write(msg)


    def add_peer(self, protoversion):
        entry = (self.remote_ip, self.kind, time(), protoversion)
        self.factory.peers[self.remote_nodeid] = entry



# Splitinto NCRecvFactory and NCSendFactory (also reconsider the names...:/)
class NCFactory(Factory):
    def __init__(self):
        pass

    def startFactory(self):
        self.peers = {}
        self.numProtocols = 0
        self.nodeid = cryptotools.generate_nodeid()[:10]
        _print(" [ ] NODEID:", self.nodeid)

    def stopFactory(self):
        pass

    def buildProtocol(self, addr):
        return NCProtocol(self, "GETHELLO", "LISTENER")

def gotProtocol(p):
    # ClientFactory instead
    p.send_HELLO()



if __name__ == "__main__":
    DEFAULT_PORT = 5005
    try:
        endpoint = TCP4ServerEndpoint(reactor, 4545, interface="127.0.0.1")
        _print(" [ ] LISTEN:", "127.0.0.1", ":", 4545)
        ncfactory = NCFactory()
        endpoint.listen(ncfactory)
    except CannotListenError:
        _print("[!] Address in use")
        raise SystemExit


    # connect to bootstrap addresses
    _print(" [ ] Trying to connect to bootstrap hosts:")
    for bootstrap in BOOTSTRAP_NODES + [a+":"+str(DEFAULT_PORT) for a in []]:

        _print("     [*] ", bootstrap)
        host, port = bootstrap.split(":")
        point = TCP4ClientEndpoint(reactor, host, int(port))
        d = connectProtocol(point, NCProtocol(ncfactory, "SENDHELLO", "LISTENER"))
        d.addCallback(gotProtocol)
    reactor.run()
