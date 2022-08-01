#!/usr/bin/env python3

from key_slots import AutosarKeySlots
from memory_update_protocol import *


# Generate Memory Update Protocol Message (Basic SHE)
def basic_she_memory_update_protocol() :
    # Update key data
    input_key = MemoryUpdateInfo(
        UID           = bytes.fromhex('000000000000000000000000000001'),
        KEY_NEW       = bytes.fromhex('0f0e0d0c0b0a09080706050403020100'),
        KEY_AuthID    = bytes.fromhex('000102030405060708090a0b0c0d0e0f'),
        ID            = AutosarKeySlots.KEY_1,
        AuthID        = AutosarKeySlots.MASTER_ECU_KEY,
        C_ID          = 0x01, # Counter value
        F_ID          = 0x00  # Flags
    )

    # Generate Message
    msg  = generate_message_basic(input_key)

    # Print Message
    print("M1 : " ,msg.M1.hex())
    print("M2 : " ,msg.M2.hex())
    print("M3 : " ,msg.M3.hex())
    print("M4 : " ,msg.M4.hex())
    print("M5 : " ,msg.M5.hex())

# Generate Memory Update Protocol Message (SHE+)
def extend_she_memory_update_protocol() :
    # Update key data
    input_key = MemoryUpdateInfo(
        UID           = bytes.fromhex('000000000000000000000000000001'),
        KEY_NEW       = bytes.fromhex('0f0e0d0c0b0a09080706050403020100'),
        KEY_AuthID    = bytes.fromhex('000102030405060708090a0b0c0d0e0f'),
        ID            = AutosarKeySlots.KEY_1,
        AuthID        = AutosarKeySlots.MASTER_ECU_KEY,
        C_ID          = 0x01, # Counter value
        F_ID          = 0x00  # Flags
    )

    # Generate Message
    msg  = generate_message_extend(input_key)

    # Print Message
    print("M1 : " ,msg.M1.hex())
    print("M2 : " ,msg.M2.hex())
    print("M3 : " ,msg.M3.hex())
    print("M4 : " ,msg.M4.hex())
    print("M5 : " ,msg.M5.hex())

# Generate Memory Update Protocol Message (Advanced)
def advanced_she_memory_update_protocol() :
    # Update key data
    input_key = MemoryUpdateInfo(
        UID           = bytes.fromhex('000000000000000000000000000001'),
        KEY_NEW       = bytes.fromhex('0f0e0d0c0b0a09080706050403020100'),
        KEY_AuthID    = bytes.fromhex('000102030405060708090a0b0c0d0e0f'),
        ID            = AutosarKeySlots.KEY_1,
        AuthID        = AutosarKeySlots.MASTER_ECU_KEY,
        C_ID          = 0x01, # Counter value
        F_ID          = 0x00  # Flags
    )

    # Define keybank indexes
    KEY_UPDATE_ENC_C = dict([
        ('BANK_1_10' ,'010153484500800000000000000000b0'),
        ('BANK_11_20','018153484500800000000000000000b0'),
        ('BANK_21_30','019153484500800000000000000000b0'),
        ('BANK_31_40','01a153484500800000000000000000b0'),
        ('BANK_41_50','01b153484500800000000000000000b0'),
        ('BANK_51_60','01c153484500800000000000000000b0'),
        ('BANK_61_70','01d153484500800000000000000000b0'),
        ('BANK_71_80','01e153484500800000000000000000b0'),
        ('BANK_81_90','01f153484500800000000000000000b0')
    ])
    KEY_UPDATE_MAC_C = dict([
        ('BANK_1_10' ,'010253484500800000000000000000b0'),
        ('BANK_11_20','018253484500800000000000000000b0'),
        ('BANK_21_30','019253484500800000000000000000b0'),
        ('BANK_31_40','01a253484500800000000000000000b0'),
        ('BANK_41_50','01b253484500800000000000000000b0'),
        ('BANK_51_60','01c253484500800000000000000000b0'),
        ('BANK_61_70','01d253484500800000000000000000b0'),
        ('BANK_71_80','01e253484500800000000000000000b0'),
        ('BANK_81_90','01f253484500800000000000000000b0')
    ])

    for bank in KEY_UPDATE_ENC_C.keys():
        # Generate Message for keys 1-10
        msg  = generate_message(input_key, bytes.fromhex(KEY_UPDATE_ENC_C[bank]), bytes.fromhex(KEY_UPDATE_MAC_C[bank]))

        # Print Message
        print("Bank " + bank )
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

    print('-- Memory Update Protocol(Advanced) --')
    advanced_she_memory_update_protocol()

if __name__ == '__main__':
    main()
