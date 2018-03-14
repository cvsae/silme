#!/usr/bin/python
# Copyright (c) 2018 CVSC
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from main import *
from version import _version
import sys




def CalculateDiff():
    """ Calculate current difficulty """
    # diff is minimun difficulty target / current_target 
    p = bits2target(0x1d00ffff)
    y = bits2target(GetNextWorkRequired())
    return p / y


def GetBestHeight():
    # return best heigh 
    return CBlockchainDB().getBestHeight()

def GetBestHash():
    # return the best hash in blockchain
    return CBlockchainDB().GetBestHash()


def GetDifficulty():
    # return the difficulty
    return CalculateDiff()


def GetMyAddresses():
    # return all addresses that we own
    return CWalletDB().GetMyAddresses()


def GetNewAddress():
    # return new address
    key = GenerateNewKey()
    return CKey().GetAddress(key)

def NetHashRate():
    # return network hashrate in ghs
    return NetworkHashrate()

def GetBalance():
    return CWalletDB().GetBalance()


def MemCount():
    return Mempool().counttxs()


def Version():
    return _version

