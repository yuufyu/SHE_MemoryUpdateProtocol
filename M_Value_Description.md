# M1

| UID' | ID | AuthID |
| --- | --- | --- |
| 120 bits | 4 bits | 4 bits | 

M1 = UID' | ID | AuthID

# M2

K1 is the derived encryption key used in M2

K1 = KDF(K<sub>AuthID</sub>, KEY_UPDATE_ENC_C)

C<sub>ID</sub> = 28 bit counter value for key

F<sub>ID</sub> = 5 bit key flag value

M2 = ENC<sub>CBC,K1,IV=0</sub>(C<sub>ID</sub> | F<sub>ID</sub> | "0...0"<sub>95</sub> | K<sub>ID</sub>)

# M3

K2 is the derived CMAC authentication key used in M3.

K2 = KDF(K<sub>AuthID</sub>, KEY_UPDATE_MAC_C)
  
M3 = CMAC<sub>K2</sub>(M1|M2)

# M4

K3 is the derived encryption key used for

K3 = KDF(K<sub>ID</sub>, KEY_UPDATE_ENC_C)

M4 = UID | ID | AuthID | ENC<sub>CBC,K3,IV=0</sub>(C<sub>ID</sub>)

# M5

K4 = KDF(K<sub>ID</sub>, KEY_UPDATE_MAC_C)

M5 = CMAC<sub>K4</sub>(M4)

# Key Derivation

Keys are derived using the Miyaguchi-Preneel compression algorithm based on [NIST800_108]. Derived
keys are calculated by compressing the correctly preprocessed concatenation of a secret K and
a constant C.

KDF(K,C) = AES-MP(K | C)
