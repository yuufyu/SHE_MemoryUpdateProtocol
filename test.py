import unittest
from memory_update_protocol import MemoryUpdateProtocol, mp_compress

class TestMemoryUpdateProtocol(unittest.TestCase) :
    def test_memory_update_protocol(self) :
        test_cases = [
            # Basic SHE
            (
                {
                    'uid'              : '000000000000000000000000000001',
                    'key_new'          : '0f0e0d0c0b0a09080706050403020100',
                    'key_auth'         : '000102030405060708090a0b0c0d0e0f',
                    'id'               : 0x04,
                    'auth_id'          : 0x01,
                    'counter'          : 0x01,
                    'key_flags'        : 0x00,
                    'KEY_UPDATE_ENC_C' : None,
                    'KEY_UPDATE_MAC_C' : None
                },
                {
                    'k1'               : '118a46447a770d87828a69c222e2d17e',
                    'k2'               : '2ebb2a3da62dbd64b18ba6493e9fbe22',
                    'k3'               : 'ed2de7864a47f6bac319a9dc496a788f',
                    'k4'               : 'ec9386fefaa1c598246144343de5f26a',
                    'm1'               : '00000000000000000000000000000141',
                    'm2'               : '2b111e2d93f486566bcbba1d7f7a9797c94643b050fc5d4d7de14cff682203c3',
                    'm3'               : 'b9d745e5ace7d41860bc63c2b9f5bb46',
                    'm4'               : '00000000000000000000000000000141b472e8d8727d70d57295e74849a27917',
                    'm5'               : '820d8d95dc11b4668878160cb2a4e23e'
                }
            ),
            (
                {
                    'uid'              : '000000000000000000000000000000',
                    'key_new'          : '0f0e0d0c0b0a09080706050403020100',
                    'key_auth'         : '000102030405060708090a0b0c0d0e0f',
                    'id'               : 0x01,
                    'auth_id'          : 0x01,
                    'counter'          : 0x01,
                    'key_flags'        : 0x04,
                    'KEY_UPDATE_ENC_C' : None,
                    'KEY_UPDATE_MAC_C' : None
                },
                {
                    'k1'               : '118a46447a770d87828a69c222e2d17e',
                    'k2'               : '2ebb2a3da62dbd64b18ba6493e9fbe22',
                    'k3'               : 'ed2de7864a47f6bac319a9dc496a788f',
                    'k4'               : 'ec9386fefaa1c598246144343de5f26a',
                    'm1'               : '00000000000000000000000000000011',
                    'm2'               : '74c3a812bf192a6b52d89d79d9b04ac87f19526c70790d7fcdb707a77dfdf5a8',
                    'm3'               : '70c1ebfa56bc2fffff1c9f33048fc294',
                    'm4'               : '00000000000000000000000000000011b472e8d8727d70d57295e74849a27917',
                    'm5'               : 'ec4a8474b925eaae19feef74620fad7f',
                }
            ),
            # SHE+
            (
                {
                    'uid'              : '000000000000000000000000000001',
                    'key_new'          : '0f0e0d0c0b0a09080706050403020100',
                    'key_auth'         : '000102030405060708090a0b0c0d0e0f',
                    'id'               : 0x04,
                    'auth_id'          : 0x01,
                    'counter'          : 0x01,
                    'key_flags'        : 0x00,
                    'KEY_UPDATE_ENC_C' : '018153484500800000000000000000B0',
                    'KEY_UPDATE_MAC_C' : '018253484500800000000000000000B0'
                },
                {
                    'k1'               : '9847689658cabed9815e657e3b7971f9',
                    'k2'               : 'e35a519f1334cd696acf0138fbc2fd1e',
                    'k3'               : '51cc37f309036093e6abfedaa5460d89',
                    'k4'               : '425e351a06132445a37ddf8173dc779e',
                    'm1'               : '00000000000000000000000000000141',
                    'm2'               : 'a6c4d8f632faed103d8e3eef2b7694a92b214b1efad16a4c32964afa37ddadef',
                    'm3'               : '22eb8f2385cb16a0082aabc106b7dbc6',
                    'm4'               : '00000000000000000000000000000141b059c21adbcb938000c9805434852637',
                    'm5'               : 'e3073b876fa53173da072802bd2c8871'
                }
            ),
            (
                {
                    'uid'              : '000000000000000000000000000001',
                    'key_new'          : '0f0e0d0c0b0a09080706050403020100',
                    'key_auth'         : '000102030405060708090a0b0c0d0e0f',
                    'id'               : 0x04,
                    'auth_id'          : 0x01,
                    'counter'          : 0x01,
                    'key_flags'        : 0x04,
                    'KEY_UPDATE_ENC_C' : '018153484500800000000000000000B0',
                    'KEY_UPDATE_MAC_C' : '018253484500800000000000000000B0'
                },
                {
                    'k1'               : '9847689658cabed9815e657e3b7971f9',
                    'k2'               : 'e35a519f1334cd696acf0138fbc2fd1e',
                    'k3'               : '51cc37f309036093e6abfedaa5460d89',
                    'k4'               : '425e351a06132445a37ddf8173dc779e',
                    'm1'               : '00000000000000000000000000000141',
                    'm2'               : 'c1a862b5d2eb7e2c3387761d01e7585c5b5141e78337c25b5ead1db37ba540a3',
                    'm3'               : 'a36302e8d8e463162acce8861fd7d668',
                    'm4'               : '00000000000000000000000000000141b059c21adbcb938000c9805434852637',
                    'm5'               : 'e3073b876fa53173da072802bd2c8871'
                }
            ),
        ]

        for data, expected in test_cases :
            # self, id, key_new, auth_id, key_auth, uid, counter, key_flags
            with self.subTest(data = data, expected = expected) :
                mup = MemoryUpdateProtocol(data['id'], bytes.fromhex(data['key_new']), data['auth_id'], bytes.fromhex(data['key_auth']), bytes.fromhex(data['uid']), data['counter'], data['key_flags'])
                if data['KEY_UPDATE_ENC_C'] and data['KEY_UPDATE_MAC_C'] :
                    mup.KEY_UPDATE_ENC_C = bytes.fromhex(data['KEY_UPDATE_ENC_C'])
                    mup.KEY_UPDATE_MAC_C = bytes.fromhex(data['KEY_UPDATE_MAC_C'])

                self.assertEqual(mup.make_k1().hex(), expected['k1'])
                self.assertEqual(mup.make_k2().hex(), expected['k2'])
                self.assertEqual(mup.make_k3().hex(), expected['k3'])
                self.assertEqual(mup.make_k4().hex(), expected['k4'])
                self.assertEqual(mup.make_m1().hex(), expected['m1'])
                self.assertEqual(mup.make_m2().hex(), expected['m2'])
                self.assertEqual(mup.make_m3().hex(), expected['m3'])
                self.assertEqual(mup.make_m4().hex(), expected['m4'])
                self.assertEqual(mup.make_m5().hex(), expected['m5'])

    def test_mp_compress(self) :
        msg = bytes.fromhex('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5180000000000000000000000000000100')
        res = mp_compress(msg)
        self.assertEqual(res.hex(), 'c7277a0dc1fb853b5f4d9cbd26be40c6')
