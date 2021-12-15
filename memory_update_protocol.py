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

# Add constant values for flags
WRITE_PROTECTION    = 0b100000
BOOT_PROTECTION     = 0b010000
DEBUGGER_PROTECTION = 0b001000
KEY_USAGE           = 0b000100
WILDCARD            = 0b000010
VERIFY_ONLY         = 0b000001

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

def decrypt_ecb(key, value):
    mode = AES.MODE_ECB
    enc  = AES.new(key, mode)
    result = enc.decrypt(value)
    return result

def decrypt_cbc(key, value, iv = bytes([0]*16)):
    mode = AES.MODE_CBC
    enc  = AES.new(key, mode, iv = iv)
    result = enc.decrypt(value)
    return result

def verify_cmac(key, msg, digest) :
    cmac = CMAC.new(key, ciphermod = AES)
    cmac.update(msg)
    try:
        cmac.verify(digest)
        return True
    except ValueError:
        return False


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
                 + ((info.F_ID << 6) & 0xC0).to_bytes(1, 'big') \
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


# Decrypt SHE M* values
def decrypt_message(KEY_AuthID, message, KEY_UPDATE_ENC_C, KEY_UPDATE_MAC_C) -> MemoryUpdateInfo:
    k1 = mp_kdf(KEY_AuthID, KEY_UPDATE_ENC_C)
    k2 = mp_kdf(KEY_AuthID, KEY_UPDATE_MAC_C)
    UID = bytes.fromhex(message.M1.hex()[0:30])
    ID = int(message.M1.hex()[30],16)
    AuthID = int(message.M1.hex()[31],16)
    dec = decrypt_cbc(k1,message.M2).hex()
    C_ID = int(dec[0:7],16)
    F_ID = int(dec[7:9],16)>>2
    KEY_NEW = bytes.fromhex(dec[32:64])
    if(verify_cmac(k2, message.M1 + message.M2, message.M3)):
        return True, MemoryUpdateInfo(KEY_NEW, KEY_AuthID, UID, ID, AuthID, C_ID,F_ID)
    else:
        return False, MemoryUpdateInfo(KEY_NEW, KEY_AuthID, UID, ID, AuthID, C_ID,F_ID)
