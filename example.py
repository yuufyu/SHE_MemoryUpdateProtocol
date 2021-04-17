#!/usr/bin/env python3

import binascii
from memory_update_protocol import MemoryUpdateProtocol, mp_compress

def basic_she_memory_update_protocol() :
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
    she = MemoryUpdateProtocol(id, key_new, auth_id, key_auth, uid, counter, key_flags)
    k1 = she.make_k1()
    k2 = she.make_k2()
    k3 = she.make_k3()
    k4 = she.make_k4()
    m1 = she.make_m1()
    m2 = she.make_m2()
    m3 = she.make_m3()
    m4 = she.make_m4()
    m5 = she.make_m5()

    print("K1 : " ,binascii.hexlify(k1))
    print("K2 : " ,binascii.hexlify(k2))
    print("K3 : " ,binascii.hexlify(k3))
    print("K4 : " ,binascii.hexlify(k4))

    print("M1 : " ,binascii.hexlify(m1))
    print("M2 : " ,binascii.hexlify(m2))
    print("M3 : " ,binascii.hexlify(m3))
    print("M4 : " ,binascii.hexlify(m4))
    print("M5 : " ,binascii.hexlify(m5))


def extend_she_memory_update_protocol() :
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
    she = MemoryUpdateProtocol(id, key_new, auth_id, key_auth, uid, counter, key_flags)

    she.KEY_UPDATE_ENC_C = binascii.unhexlify(KEY_UPDATE_ENC_C_Extend)
    she.KEY_UPDATE_MAC_C = binascii.unhexlify(KEY_UPDATE_MAC_C_Extend)

    k1 = she.make_k1()
    k2 = she.make_k2()
    k3 = she.make_k3()
    k4 = she.make_k4()
    m1 = she.make_m1()
    m2 = she.make_m2()
    m3 = she.make_m3()
    m4 = she.make_m4()
    m5 = she.make_m5()

    print("K1 : " ,binascii.hexlify(k1))
    print("K2 : " ,binascii.hexlify(k2))
    print("K3 : " ,binascii.hexlify(k3))
    print("K4 : " ,binascii.hexlify(k4))

    print("M1 : " ,binascii.hexlify(m1))
    print("M2 : " ,binascii.hexlify(m2))
    print("M3 : " ,binascii.hexlify(m3))
    print("M4 : " ,binascii.hexlify(m4))
    print("M5 : " ,binascii.hexlify(m5))
    
def extend_she_memory_update_protocol2() :
    KEY_UPDATE_ENC_C_Extend = '018153484500800000000000000000B0'
    KEY_UPDATE_MAC_C_Extend = '018253484500800000000000000000B0'

    uid_str = '000000000000000000000000000001'
    key_new_str  = '0f0e0d0c0b0a09080706050403020100'
    key_auth_str = '000102030405060708090a0b0c0d0e0f'
    id = 4
    auth_id = 1
    counter = 1
    key_flags = 0x04

    uid      = binascii.unhexlify(uid_str)
    key_new  = binascii.unhexlify(key_new_str)
    key_auth = binascii.unhexlify(key_auth_str)

    # self, id, key_new, auth_id, key_auth, uid, counter, key_flags
    she = MemoryUpdateProtocol(id, key_new, auth_id, key_auth, uid, counter, key_flags)

    she.KEY_UPDATE_ENC_C = binascii.unhexlify(KEY_UPDATE_ENC_C_Extend)
    she.KEY_UPDATE_MAC_C = binascii.unhexlify(KEY_UPDATE_MAC_C_Extend)

    k1 = she.make_k1()
    k2 = she.make_k2()
    k3 = she.make_k3()
    k4 = she.make_k4()
    m1 = she.make_m1()
    m2 = she.make_m2()
    m3 = she.make_m3()
    m4 = she.make_m4()
    m5 = she.make_m5()

    print("K1 : " ,binascii.hexlify(k1))
    print("K2 : " ,binascii.hexlify(k2))
    print("K3 : " ,binascii.hexlify(k3))
    print("K4 : " ,binascii.hexlify(k4))

    print("M1 : " ,binascii.hexlify(m1))
    print("M2 : " ,binascii.hexlify(m2))
    print("M3 : " ,binascii.hexlify(m3))
    print("M4 : " ,binascii.hexlify(m4))
    print("M5 : " ,binascii.hexlify(m5))

def miyaguchi_comp() :
    msg = binascii.unhexlify('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5180000000000000000000000000000100')
    res = mp_compress(msg)
    # output c7277a0dc1fb853b5f4d9cbd26be40c6
    print(binascii.hexlify(res))

def main() :
    print('-- SHE test --')
    basic_she_memory_update_protocol()

    print('-- SHE Extend test--')
    extend_she_memory_update_protocol()
    
    print('-- SHE Extend2 test--')
    extend_she_memory_update_protocol2()

    miyaguchi_comp()

if __name__ == '__main__':
    main()

# EOF