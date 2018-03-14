import hmac
import json
import cryptotools

# generate_nodeid() uses SHA256 so this will prevent replay-attacks,
# because every message will have a different nonce.
# It's not nessecary to compare the nonce, HMAC already gives message
# integrety.
nonce = lambda: cryptotools.generate_nodeid()
incr_nonce = lambda env: format(int(env["nonce"], 16) + 1, 'x')

class InvalidSignatureError(Exception):
    pass

class InvalidNonceError(Exception):
    pass

def make_envelope(msgtype, msg, nodeid):
    msg['nodeid'] = nodeid
    msg['nonce'] =  nonce()
    data = json.dumps(msg, encoding='latin1')

    sign = hmac.new(nodeid, data)
    envelope = {'data': msg,
                'sign': sign.hexdigest(),
                'msgtype': msgtype}
    #print "make_envelope:", envelope
    return json.dumps(envelope, encoding='latin1')



def envelope_decorator(nodeid, func):
    msgtype = func.__name__.split("_")[0]
    def inner(*args, **kwargs):
        return make_envelope(msgtype, func(*args, **kwargs), nodeid)
    return inner

# ------

def create_ackhello(nodeid):
    msg = {}
    return make_envelope("ackhello", msg, nodeid)


def create_ask_need_sync(nodeid, hash, height):
    msg = {"hash": hash, "height": height}
    return make_envelope("ask_needsync", msg, nodeid)


def create_send_mempool(nodeid, transactions):
    msg = {"transactions": transactions}
    return make_envelope("getmemppol", msg, nodeid)


def create_reply_need_sync(nodeid, height, bcount):
    msg = {"need": True, "height": height, "blocks": bcount}
    return make_envelope("needsync", msg, nodeid)


def create_getblocks(nodeid, height):
    msg = {"height": height}
    return make_envelope("getblocks", msg, nodeid)


def getblock(nodeid, raw, coinbase, transactions, nonce):
    msg = {"raw": raw, "coinbase": coinbase, "transactions": transactions, "b_nonce": nonce}
    return make_envelope("getblock", msg, nodeid)





def create_hello(nodeid, version):
    msg = {'version': version}
    return make_envelope("hello", msg, nodeid)

def create_ping(nodeid):
    msg = {}
    return make_envelope("ping", msg, nodeid)

def create_pong(nodeid):
    msg = {}
    return make_envelope("pong", msg, nodeid)

def create_getaddr(nodeid):
    msg = {}
    return make_envelope("getaddr", msg, nodeid)

def create_addr(nodeid, nodes):
    msg = {'nodes': nodes}
    return make_envelope("addr", msg, nodeid)
# -------

def read_envelope(message):
    return json.loads(message, encoding='utf-8')

def read_message(message):
    """Read and parse the message into json. Validate the signature
    and return envelope['data']
    """
    envelope = json.loads(message)
    nodeid = str(envelope['data']['nodeid'])
    signature = str(envelope['sign'])
    msg = json.dumps(envelope['data'])
    verify_sign = hmac.new(nodeid, msg)
    #print "read_message:", msg
    return envelope['data']
    
