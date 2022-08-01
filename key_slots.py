"""
This file contains identification of memory slots.

"""

from enum import Enum

__all__ = ["AutosarKeySlots", "KeySlots"]


class KeySlots(Enum):
    """
    Enum to be inherited by user.
    Every OEM may want it's own key slot identification.

    """


class AutosarKeySlots(KeySlots):
    """
    Enum holds memory slot identification based on
    `Specification of Secure Hardware Extensions, AUTOSAR FO R19-11`.

    """

    SECRET_KEY = 0x0
    MASTER_ECU_KEY = 0x1
    BOOT_MAC_KEY = 0x2
    BOOT_MAC = 0x3
    KEY_1 = 0x4
    KEY_2 = 0x5
    KEY_3 = 0x6
    KEY_4 = 0x7
    KEY_5 = 0x8
    KEY_6 = 0x9
    KEY_7 = 0xA
    KEY_8 = 0xB
    KEY_9 = 0xC
    KEY_10 = 0xD
    RAM_KEY = 0xE
