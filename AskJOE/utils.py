import re
import struct


def pack_constant(const):
    byte_array = []
    if const["size"] == "B":
        byte_array = const["array"]
    elif const["size"] == "L":
        for val in const["array"]:
            byte_array += list(map(lambda x: x if isinstance(x, int) else ord(x), struct.pack("<L", val)))
    elif const["size"] == "Q":
        for val in const["array"]:
            byte_array += list(map(lambda x: x if isinstance(x, int) else ord(x), struct.pack("<Q", val)))
    return bytes(bytearray(byte_array))
