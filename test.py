import unittest
from memory_update_protocol import *

class TestMemoryUpdateProtocol(unittest.TestCase) :
    def test_generate_message_basic(self) :
        test_cases = [
            (
                {
                    'UID'              : bytes.fromhex('000000000000000000000000000001'),
                    'KEY_NEW'          : bytes.fromhex('0f0e0d0c0b0a09080706050403020100'),
                    'KEY_AuthID'       : bytes.fromhex('000102030405060708090a0b0c0d0e0f'),
                    'ID'               : 0x04,
                    'AuthID'           : 0x01,
                    'C_ID'             : 0x01,
                    'F_ID'             : 0x00
                },
                {
                    'M1'               : bytes.fromhex('00000000000000000000000000000141'),
                    'M2'               : bytes.fromhex('2b111e2d93f486566bcbba1d7f7a9797c94643b050fc5d4d7de14cff682203c3'),
                    'M3'               : bytes.fromhex('b9d745e5ace7d41860bc63c2b9f5bb46'),
                    'M4'               : bytes.fromhex('00000000000000000000000000000141b472e8d8727d70d57295e74849a27917'),
                    'M5'               : bytes.fromhex('820d8d95dc11b4668878160cb2a4e23e')
                }
            ),
            (
                {
                    'UID'              : bytes.fromhex('000000000000000000000000000000'),
                    'KEY_NEW'          : bytes.fromhex('0f0e0d0c0b0a09080706050403020100'),
                    'KEY_AuthID'       : bytes.fromhex('000102030405060708090a0b0c0d0e0f'),
                    'ID'               : 0x01,
                    'AuthID'           : 0x01,
                    'C_ID'             : 0x01,
                    'F_ID'             : 0x04
                },
                {
                    'M1'               : bytes.fromhex('00000000000000000000000000000011'),
                    'M2'               : bytes.fromhex('74c3a812bf192a6b52d89d79d9b04ac87f19526c70790d7fcdb707a77dfdf5a8'),
                    'M3'               : bytes.fromhex('70c1ebfa56bc2fffff1c9f33048fc294'),
                    'M4'               : bytes.fromhex('00000000000000000000000000000011b472e8d8727d70d57295e74849a27917'),
                    'M5'               : bytes.fromhex('ec4a8474b925eaae19feef74620fad7f')
                }
            )
        ]

        for input, expected in test_cases :
            with self.subTest(input = input, expected = expected) :
                info = MemoryUpdateInfo(** input)
                msg  = generate_message_basic(info)
                self.assertEqual(msg.M1, expected['M1'])
                self.assertEqual(msg.M2, expected['M2'])
                self.assertEqual(msg.M3, expected['M3'])
                self.assertEqual(msg.M4, expected['M4'])
                self.assertEqual(msg.M5, expected['M5'])

    def test_generate_message_extend(self) :
        test_cases = [
            (
                {
                    'UID'              : bytes.fromhex('000000000000000000000000000001'),
                    'KEY_NEW'          : bytes.fromhex('0f0e0d0c0b0a09080706050403020100'),
                    'KEY_AuthID'       : bytes.fromhex('000102030405060708090a0b0c0d0e0f'),
                    'ID'               : 0x04,
                    'AuthID'           : 0x01,
                    'C_ID'             : 0x01,
                    'F_ID'             : 0x00,
                },
                {
                    'M1'               : bytes.fromhex('00000000000000000000000000000141'),
                    'M2'               : bytes.fromhex('a6c4d8f632faed103d8e3eef2b7694a92b214b1efad16a4c32964afa37ddadef'),
                    'M3'               : bytes.fromhex('22eb8f2385cb16a0082aabc106b7dbc6'),
                    'M4'               : bytes.fromhex('00000000000000000000000000000141b059c21adbcb938000c9805434852637'),
                    'M5'               : bytes.fromhex('e3073b876fa53173da072802bd2c8871')
                }
            ),
            (
                {
                    'UID'              : bytes.fromhex('000000000000000000000000000001'),
                    'KEY_NEW'          : bytes.fromhex('0f0e0d0c0b0a09080706050403020100'),
                    'KEY_AuthID'       : bytes.fromhex('000102030405060708090a0b0c0d0e0f'),
                    'ID'               : 0x04,
                    'AuthID'           : 0x01,
                    'C_ID'             : 0x01,
                    'F_ID'             : 0x04,
                },
                {
                    'M1'               : bytes.fromhex('00000000000000000000000000000141'),
                    'M2'               : bytes.fromhex('c1a862b5d2eb7e2c3387761d01e7585c5b5141e78337c25b5ead1db37ba540a3'),
                    'M3'               : bytes.fromhex('a36302e8d8e463162acce8861fd7d668'),
                    'M4'               : bytes.fromhex('00000000000000000000000000000141b059c21adbcb938000c9805434852637'),
                    'M5'               : bytes.fromhex('e3073b876fa53173da072802bd2c8871')
                }
            )
        ]

        for input, expected in test_cases :
            with self.subTest(input = input, expected = expected) :
                info = MemoryUpdateInfo(** input)
                msg  = generate_message_extend(info)
                self.assertEqual(msg.M1, expected['M1'])
                self.assertEqual(msg.M2, expected['M2'])
                self.assertEqual(msg.M3, expected['M3'])
                self.assertEqual(msg.M4, expected['M4'])
                self.assertEqual(msg.M5, expected['M5'])

    def test_mp_compress(self) :
        msg = bytes.fromhex('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5180000000000000000000000000000100')
        self.assertEqual(mp_compress(msg), bytes.fromhex('c7277a0dc1fb853b5f4d9cbd26be40c6'))

    def test_decode_message(self) :
        test_cases = [
            (
                {
                    'UID'              : bytes.fromhex('000000000000000000000000000001'),
                    'KEY_NEW'          : bytes.fromhex('0f0e0d0c0b0a09080706050403020100'),
                    'KEY_AuthID'       : bytes.fromhex('000102030405060708090a0b0c0d0e0f'),
                    'ID'               : 0x04,
                    'AuthID'           : 0x01,
                    'C_ID'             : 0x01,
                    'F_ID'             : 0x00
                },
                {
                    'M1'               : bytes.fromhex('00000000000000000000000000000141'),
                    'M2'               : bytes.fromhex('2b111e2d93f486566bcbba1d7f7a9797c94643b050fc5d4d7de14cff682203c3'),
                    'M3'               : bytes.fromhex('b9d745e5ace7d41860bc63c2b9f5bb46'),
                    'M4'               : bytes.fromhex('00000000000000000000000000000141b472e8d8727d70d57295e74849a27917'),
                    'M5'               : bytes.fromhex('820d8d95dc11b4668878160cb2a4e23e')
                }
            ),
            (
                {
                    'UID'              : bytes.fromhex('000000000000000000000000000000'),
                    'KEY_NEW'          : bytes.fromhex('0f0e0d0c0b0a09080706050403020100'),
                    'KEY_AuthID'       : bytes.fromhex('000102030405060708090a0b0c0d0e0f'),
                    'ID'               : 0x01,
                    'AuthID'           : 0x01,
                    'C_ID'             : 0x01,
                    'F_ID'             : 0x04
                },
                {
                    'M1'               : bytes.fromhex('00000000000000000000000000000011'),
                    'M2'               : bytes.fromhex('74c3a812bf192a6b52d89d79d9b04ac87f19526c70790d7fcdb707a77dfdf5a8'),
                    'M3'               : bytes.fromhex('70c1ebfa56bc2fffff1c9f33048fc294'),
                    'M4'               : bytes.fromhex('00000000000000000000000000000011b472e8d8727d70d57295e74849a27917'),
                    'M5'               : bytes.fromhex('ec4a8474b925eaae19feef74620fad7f')
                }
            )
        ]
        for input, expected in test_cases :
            with self.subTest(input = input, expected = expected) :
                info = MemoryUpdateInfo(** input)
                msg = MemoryUpdateMessage(** expected)
                result, decode = decrypt_message(info.KEY_AuthID, msg, bytes.fromhex('010153484500800000000000000000b0'), bytes.fromhex('010253484500800000000000000000b0'))
                self.assertTrue(result)
                self.assertEqual(decode.UID, info.UID)
                self.assertEqual(decode.KEY_NEW, info.KEY_NEW)
                self.assertEqual(decode.KEY_AuthID, info.KEY_AuthID)
                self.assertEqual(decode.ID, info.ID)
                self.assertEqual(decode.AuthID, info.AuthID)
                self.assertEqual(decode.C_ID, info.C_ID)
                self.assertEqual(decode.F_ID, info.F_ID)

if __name__ == '__main__':
    unittest.main()
