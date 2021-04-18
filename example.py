#!/usr/bin/env python3

from memory_update_protocol import *

def basic_she_memory_update_protocol() :
    input_key = MemoryUpdateInfo(
        UID           = bytes.fromhex('000000000000000000000000000001'),
        KEY_NEW       = bytes.fromhex('0f0e0d0c0b0a09080706050403020100'),
        KEY_AuthID    = bytes.fromhex('000102030405060708090a0b0c0d0e0f'),
        ID            = 0x04,
        AuthID        = 0x01,
        C_ID          = 0x01, # Counter value
        F_ID          = 0x00  # Flags
    )

    msg  = generate_message_basic(input_key)
    print("M1 : " ,msg.M1.hex())
    print("M2 : " ,msg.M2.hex())
    print("M3 : " ,msg.M3.hex())
    print("M4 : " ,msg.M4.hex())
    print("M5 : " ,msg.M5.hex())

def extend_she_memory_update_protocol() :
    input_key = MemoryUpdateInfo(
        UID           = bytes.fromhex('000000000000000000000000000001'),
        KEY_NEW       = bytes.fromhex('0f0e0d0c0b0a09080706050403020100'),
        KEY_AuthID    = bytes.fromhex('000102030405060708090a0b0c0d0e0f'),
        ID            = 0x04,
        AuthID        = 0x01,
        C_ID          = 0x01, # Counter value
        F_ID          = 0x00  # Flags
    )

    msg  = generate_message_extend(input_key)
    print("M1 : " ,msg.M1.hex())
    print("M2 : " ,msg.M2.hex())
    print("M3 : " ,msg.M3.hex())
    print("M4 : " ,msg.M4.hex())
    print("M5 : " ,msg.M5.hex())
   
def main() :
    print('-- Memory Update Protocol(Basic SHE) --')
    basic_she_memory_update_protocol()

    print('-- Memory Update Protocol(SHE+) --')
    extend_she_memory_update_protocol()

if __name__ == '__main__':
    main()
