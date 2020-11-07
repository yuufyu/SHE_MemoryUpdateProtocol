#!/usr/bin/env python3
# -*- mode: python; coding: utf-8-unix -*-

import binascii
from SHE_MemoryUpdateProtocol import SHE_MemoryUpdateProtocolGenerator, MiyaguchiPreneel_Compression

def test_SHE_Basic() :
    uid_str = '000000000000000000000000000001'
    key_new_str  = '0f0e0d0c0b0a09080706050403020100'
    key_auth_str = '000102030405060708090a0b0c0d0e0f'
    id = 4
    auth_id = 1
    counter = 1
    key_flags = 0

    uid      = binascii.unhexlify(uid_str)
    key_new  = binascii.unhexlify(key_new_str)
    key_auth = binascii.unhexlify(key_auth_str)

    # self, id, key_new, auth_id, key_auth, uid, counter, key_flags
    she = SHE_MemoryUpdateProtocolGenerator(id, key_new, auth_id, key_auth, uid, counter, key_flags)
    k1 = she.makeK1()
    k2 = she.makeK2()
    k3 = she.makeK3()
    k4 = she.makeK4()
    m1 = she.makeM1()
    m2 = she.makeM2()
    m3 = she.makeM3()
    m4 = she.makeM4()
    m5 = she.makeM5()

    print("K1 : " ,binascii.hexlify(k1))
    print("K2 : " ,binascii.hexlify(k2))
    print("K3 : " ,binascii.hexlify(k3))
    print("K4 : " ,binascii.hexlify(k4))

    print("M1 : " ,binascii.hexlify(m1))
    print("M2 : " ,binascii.hexlify(m2))
    print("M3 : " ,binascii.hexlify(m3))
    print("M4 : " ,binascii.hexlify(m4))
    print("M5 : " ,binascii.hexlify(m5))


def test_SHE_Extend() :
    KEY_UPDATE_ENC_C_Extend = '018153484500800000000000000000B0'
    KEY_UPDATE_MAC_C_Extend = '018253484500800000000000000000B0'

    uid_str = '000000000000000000000000000001'
    key_new_str  = '0f0e0d0c0b0a09080706050403020100'
    key_auth_str = '000102030405060708090a0b0c0d0e0f'
    id = 4
    auth_id = 1
    counter = 1
    key_flags = 0

    uid      = binascii.unhexlify(uid_str)
    key_new  = binascii.unhexlify(key_new_str)
    key_auth = binascii.unhexlify(key_auth_str)

    # self, id, key_new, auth_id, key_auth, uid, counter, key_flags
    she = SHE_MemoryUpdateProtocolGenerator(id, key_new, auth_id, key_auth, uid, counter, key_flags)

    she.KEY_UPDATE_ENC_C = binascii.unhexlify(KEY_UPDATE_ENC_C_Extend)
    she.KEY_UPDATE_MAC_C = binascii.unhexlify(KEY_UPDATE_MAC_C_Extend)

    k1 = she.makeK1()
    k2 = she.makeK2()
    k3 = she.makeK3()
    k4 = she.makeK4()
    m1 = she.makeM1()
    m2 = she.makeM2()
    m3 = she.makeM3()
    m4 = she.makeM4()
    m5 = she.makeM5()

    print("K1 : " ,binascii.hexlify(k1))
    print("K2 : " ,binascii.hexlify(k2))
    print("K3 : " ,binascii.hexlify(k3))
    print("K4 : " ,binascii.hexlify(k4))

    print("M1 : " ,binascii.hexlify(m1))
    print("M2 : " ,binascii.hexlify(m2))
    print("M3 : " ,binascii.hexlify(m3))
    print("M4 : " ,binascii.hexlify(m4))
    print("M5 : " ,binascii.hexlify(m5))

def test_miyaguchi_comp() :
    msg = binascii.unhexlify('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5180000000000000000000000000000100')
    res = MiyaguchiPreneel_Compression(msg)
    # output c7277a0dc1fb853b5f4d9cbd26be40c6
    print(binascii.hexlify(res))

def main() :
    print('-- SHE test --')
    test_SHE_Basic()

    print('-- SHE Extend test--')
    test_SHE_Extend()

    test_miyaguchi_comp()

if __name__ == '__main__':
    main()

# EOF