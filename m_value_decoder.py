
#!/usr/bin/env python3

from memory_update_protocol import *

# Decode M1-M3 values given KEY_AuthID
def basic_decode() :
    # Update key data
    input_data = MemoryUpdateInfo(
        UID           = bytes.fromhex('000000000000000000000000000001'),
        KEY_NEW       = bytes.fromhex('0f0e0d0c0b0a09080706050403020100'),
        KEY_AuthID    = bytes.fromhex('000102030405060708090a0b0c0d0e0f'),
        ID            = 0x04,
        AuthID        = 0x01,
        C_ID          = 32, # Counter value
        #F_ID          = WRITE_PROTECTION | BOOT_PROTECTION | DEBUGGER_PROTECTION | KEY_USAGE | WILDCARD | VERIFY_ONLY
        F_ID          = WRITE_PROTECTION | BOOT_PROTECTION | DEBUGGER_PROTECTION | KEY_USAGE | WILDCARD
    )

    print("Input Values")
    print("======")
    print("UID        : ", input_data.UID.hex())
    print("KEY_NEW    : ", input_data.KEY_NEW.hex())
    print("KEY_AuthID : ", input_data.KEY_AuthID.hex())
    print("ID         : ", hex(input_data.ID))
    print("AuthID     : ", hex(input_data.AuthID))
    print("C_ID       : ", hex(input_data.C_ID))
    print("F_ID       :  0b" + format(input_data.F_ID, '0>6b'))
    print("WRITE_PROTECTION    : ", (input_data.F_ID & WRITE_PROTECTION) == WRITE_PROTECTION)
    print("BOOT_PROTECTION     : ", (input_data.F_ID & BOOT_PROTECTION) == BOOT_PROTECTION)
    print("DEBUGGER_PROTECTION : ", (input_data.F_ID & DEBUGGER_PROTECTION) == DEBUGGER_PROTECTION)
    print("KEY_USAGE           : ", (input_data.F_ID & KEY_USAGE) == KEY_USAGE)
    print("WILDCARD            : ", (input_data.F_ID & WILDCARD) == WILDCARD)
    print("VERIFY_ONLY (SHE+)  : ", (input_data.F_ID & VERIFY_ONLY) == VERIFY_ONLY)
    print("======")

    # Generate Message
    msg  = generate_message_basic(input_data)

    # Print Message
    print("Encrypted Values")
    print("======")
    print("M1 : " ,msg.M1.hex())
    print("M2 : " ,msg.M2.hex())
    print("M3 : " ,msg.M3.hex())

    # Decrypt the message using input_data.KEY_AuthID as the authorization key
    status, params = decrypt_message(input_data.KEY_AuthID, msg, bytes.fromhex('010153484500800000000000000000b0'), bytes.fromhex('010253484500800000000000000000b0'))
    if(status):
        print("")
        print("Decrypted Values")
        print("======")
        print("UID        : ", params.UID.hex())
        print("KEY_NEW    : ", params.KEY_NEW.hex())
        print("KEY_AuthID : ", params.KEY_AuthID.hex())
        print("ID         : ", hex(params.ID))
        print("AuthID     : ", hex(params.AuthID))
        print("C_ID       : ", hex(params.C_ID))
        print("F_ID       :  0b" + format(params.F_ID, '0>6b'))
        print("WRITE_PROTECTION    : ", (params.F_ID & WRITE_PROTECTION) == WRITE_PROTECTION)
        print("BOOT_PROTECTION     : ", (params.F_ID & BOOT_PROTECTION) == BOOT_PROTECTION)
        print("DEBUGGER_PROTECTION : ", (params.F_ID & DEBUGGER_PROTECTION) == DEBUGGER_PROTECTION)
        print("KEY_USAGE           : ", (params.F_ID & KEY_USAGE) == KEY_USAGE)
        print("WILDCARD            : ", (params.F_ID & WILDCARD) == WILDCARD)
        print("VERIFY_ONLY (SHE+)  : ", (params.F_ID & VERIFY_ONLY) == VERIFY_ONLY)
        print("======")
    else:
        print("M3 value invalid, could not decrypt")

def main() :
    basic_decode()

if __name__ == '__main__':
    main()
