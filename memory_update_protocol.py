#!/usr/bin/env python3
# -----------------------------------------------------------------
# SHE Memory Update Protocol
# Generate M1,M2,M3,M4,M5 message.
# -----------------------------------------------------------------

from dataclasses import dataclass
from builtins import bytes
from Crypto.Cipher import AES
from Crypto.Hash import CMAC

@dataclass
class MemoryUpdateInfo :
    KEY_NEW             : bytes
    KEY_AuthID          : bytes
    UID                 : bytes
    ID                  : int
    AuthID              : int
    C_ID                : int 
    F_ID                : int

@dataclass
class MemoryUpdateMessage :
    M1                  : bytes
    M2                  : bytes
    M3                  : bytes
    M4                  : bytes
    M5                  : bytes

def encrypt_ecb(key, value):
    mode = AES.MODE_ECB
    enc  = AES.new(key, mode)
    result = enc.encrypt(value)
    return result

def encrypt_cbc(key, value, iv = bytes([0]*16)):
    mode = AES.MODE_CBC
    enc  = AES.new(key, mode, iv = iv)
    result = enc.encrypt(value)
    return result

def generate_cmac(key, msg) :
    cmac = CMAC.new(key, ciphermod = AES)
    cmac.update(msg)
    return cmac.digest()

def array_xor(a,b):
    return bytes(x ^ y for x, y in zip(a, b))

# Miyaguchi-Preneel one-way compression function
# NOTE : data length must be  a multiple of 16byte.
def mp_compress(data):
    l = len(data)
    CHUNK_LEN = 16                # 128bit(16byte) chunks
    out = bytes([0] * CHUNK_LEN)  # Initialization vector (IV) is zero.

    for i in range(0, l, CHUNK_LEN):
        chunk = data[i : i + CHUNK_LEN]
        enc   = encrypt_ecb(out, chunk)
        out   = array_xor(array_xor(enc, chunk), out)

    return out

def mp_kdf(k, c) :
    return mp_compress(k + c)

# Generate Memory Update Protocol Message
def generate_message(info, KEY_UPDATE_ENC_C, KEY_UPDATE_MAC_C) -> MemoryUpdateMessage :
    k1 = mp_kdf(info.KEY_AuthID, KEY_UPDATE_ENC_C)
    k2 = mp_kdf(info.KEY_AuthID, KEY_UPDATE_MAC_C)
    k3 = mp_kdf(info.KEY_NEW, KEY_UPDATE_ENC_C)
    k4 = mp_kdf(info.KEY_NEW, KEY_UPDATE_MAC_C)

    m1 = info.UID + ( (info.ID << 4) | (info.AuthID & 0x0F) ).to_bytes(1, 'big')
    m2 = encrypt_cbc(k1, ((info.C_ID << 4) | (0x0F & (info.F_ID >> 2))).to_bytes(4, 'big') \
                 + ((info.F_ID << 6) & 0x03).to_bytes(1, 'big') \
                 + bytes([0]*11) \
                 + info.KEY_NEW )
    m3 = generate_cmac(k2, m1 + m2)
    m4 = m1 + encrypt_ecb(k3, ((info.C_ID << 4) | 0x08).to_bytes(4, 'big') + bytes([0]*12))
    m5 = generate_cmac(k4, m4)

    return MemoryUpdateMessage(m1, m2, m3, m4, m5)

# Generate Memory Update Protocol Message(Basic SHE)
def generate_message_basic(info) -> MemoryUpdateMessage :
    return generate_message(info, bytes.fromhex('010153484500800000000000000000B0'), bytes.fromhex('010253484500800000000000000000B0'))

# Generate Memory Update Protocol Message(SHE+)
def generate_message_extend(info) -> MemoryUpdateMessage :
    return generate_message(info, bytes.fromhex('018153484500800000000000000000B0'), bytes.fromhex('018253484500800000000000000000B0'))
