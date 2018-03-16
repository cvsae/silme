#!/usr/bin/python
# Copyright (c) 2018 CVSC
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from __future__ import print_function

import argparse
import json
from os.path import expanduser
import signal
import socket
import xmlrpclib

import ConfigParser
from rpc_commands import *
from SimpleXMLRPCServer import *


if sys.maxsize <= 2**32:
    print("Warning: it looks like you are using a 32bit system. You may experience crashes caused by mmap")


if os.getuid() == 0:
    print("Do not run this program as root!")
    print("Run the install script to create a non-privileged user.")
    sys.exit(0)


def run_rpc_command(params, electrum_rpc_port):
    cmd = params[0]
    server = xmlrpclib.ServerProxy('http://localhost:4878')
    func = getattr(server, cmd)
    r = func(*params[1:])
    
    print(json.dumps(r, indent=4, sort_keys=True))


class AltXMLRPCServer(SimpleXMLRPCServer):
    finished = False

    def register_signal(self, signum):
        signal.signal(signum, self.signal_handler)

    def signal_handler(self, signum, frame):
        print("Caught signal", signum)
        self.shutdown()

    def shutdown(self):
        self.finished = True
        return self

    def serve_forever(self):
        while not self.finished:
            server.handle_request()


if __name__ == '__main__':

    config = ConfigParser.ConfigParser()
    config.read('{}/.silme/silme.conf'.format(exanduser('~')))

    rpc_host = config.get('server', 'host')
    rpc_port = 4878

    parser = argparse.ArgumentParser()
    parser.add_argument('command', nargs='*', default=[], help='send a command to the server')
    args = parser.parse_args()

    if len(args.command) >= 1:
        try:
            run_rpc_command(args.command, rpc_port)
            sys.exit(0)
        except socket.error:
            print("Server not running")
            sys.exit(1)

    try:
        run_rpc_command(['getpid'], rpc_port)
        is_running = True
    except socket.error:
        is_running = False

    if is_running:
        print("Server already running!")
        sys.exit(1)


    server = AltXMLRPCServer((rpc_host, rpc_port))
    print("Serving on {}:{}".format(rpc_host, rpc_port))
    
    # server control
    server.register_function(pow)
    server.register_function(server.shutdown, 'stop')
    server.register_function(lambda: os.getpid(), 'getpid')
    server.register_function(Version, 'version')
    server.register_introspection_functions()
    
    # blockchain 
    server.register_function(GetBestHeight, 'getbestheight')
    server.register_function(GetBestHash, 'getbesthash')
    server.register_function(GetDifficulty, 'getdifficulty')
    server.register_function(NetHashRate, 'nethashrate')

    # wallet
    server.register_function(GetMyAddresses, 'getmyaddresses')
    server.register_function(GetNewAddress, 'getnewaddress')
    server.register_function(GetBalance, 'getbalance')

    # mining
    server.register_function(MemCount, 'mempoolcount')

    # signals
    server.register_signal(signal.SIGHUP)
    server.register_signal(signal.SIGINT)

    server.serve_forever()
    print("Server closed")
