#!/usr/bin/env python3
# -*- mode: python; coding: utf-8-unix -*-

from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from builtins import bytes

def encryptEcb(key, value):
    mode = AES.MODE_ECB
    enc  = AES.new(key, mode)
    result = enc.encrypt(value)
    return result

def encryptCbc(key, value, iv = bytes([0]*16)):
    mode = AES.MODE_CBC
    enc  = AES.new(key, mode, iv = iv)
    result = enc.encrypt(value)
    return result

def generateCMac(key, msg) :
    cmac = CMAC.new(key, ciphermod = AES)
    cmac.update(msg)
    return cmac.digest()

# -----------------------------------------------------------------
# Miyaguchi-Preneel one-way compression function
# 
# NOTE: data length must be  a multiple of 16byte.
# TODO : implement padding
# -----------------------------------------------------------------
def MiyaguchiPreneel_Compression(data):
    l = len(data)
    CHUNK_LEN = 16                # 128bit(16byte) chunks
    out = bytes([0] * CHUNK_LEN)  # Initialization vector (IV) is zero.

    for i in range(0, l, CHUNK_LEN):
        chunk = data[i : i + CHUNK_LEN]
        enc   = encryptEcb(out, chunk)
        out   = _array_xor(_array_xor(enc, chunk), out)

    return out

def _kdf_mp(k, c) :
    return MiyaguchiPreneel_Compression(k + c)

def _array_xor(a,b):
    return bytes(x ^ y for x, y in zip(a, b))

# -----------------------------------------------------------------
# SHE Memory Update Protocol
# Generate M1,M2,M3,M4,M5 message.
# -----------------------------------------------------------------
class SHE_MemoryUpdateProtocolGenerator:
    KEY_UPDATE_ENC_C = 0x010153484500800000000000000000B0.to_bytes(16, 'big')
    KEY_UPDATE_MAC_C = 0x010253484500800000000000000000B0.to_bytes(16, 'big')

    def __init__(self, id, key_new, auth_id, key_auth, uid, counter, key_flags):
        self.id        = id
        self.key_new   = key_new
        self.auth_id   = auth_id
        self.key_auth  = key_auth
        self.uid       = uid
        self.counter   = counter
        self.key_flags = key_flags
        # TODO check parameters size

    def makeK1(self) :
        return _kdf_mp(self.key_auth, self.KEY_UPDATE_ENC_C)
    
    def makeK2(self) :
        return _kdf_mp(self.key_auth, self.KEY_UPDATE_MAC_C)

    def makeK3(self) :
        return _kdf_mp(self.key_new, self.KEY_UPDATE_ENC_C)

    def makeK4(self) :
        return _kdf_mp(self.key_new, self.KEY_UPDATE_MAC_C)
    
    def makeM1(self) :
        return self.uid + ( (self.id << 4) | (self.auth_id & 0x0F) ).to_bytes(1, 'big')

    def makeM2(self) :
        data = ((self.counter << 4) | (0x0F & (self.key_flags >> 2))).to_bytes(4, 'big') \
                 + ((self.key_flags << 6) & 0x03).to_bytes(1, 'big') \
                 + bytes([0]*11) \
                 + self.key_new
        k1 = self.makeK1()
        return encryptCbc(k1, data)

    def makeM3(self) :
        m1 = self.makeM1()
        m2 = self.makeM2()
        k2 = self.makeK2()
        return generateCMac(k2, m1 + m2)

    def makeM4(self) :
        data = ((self.counter << 4) | 0x08).to_bytes(4, 'big') + bytes([0]*12)
        m1 = self.makeM1()
        k3 = self.makeK3()
        return m1 + encryptEcb(k3, data)

    def makeM5(self) :
        m4 = self.makeM4()
        k4 = self.makeK4()
        return generateCMac(k4, m4)
