#!/usr/bin/python
# Copyright (c) 2017 CVSC
# Distributed under the MIT/X11 software license, see the accompanying
# file license.blockt or http://www.opensource.org/licenses/mit-license.php.

import sqlite3 
from main import *


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




print haveReachableNode()