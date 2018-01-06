from strings import hexify, unhexify
from xor import xor
import struct

def leftrotate(val, n):
    return ((val << n) | (val >> 32 - n)) & 0xFFFFFFFF

class sha1:

    def __init__(self):
        self.h0 = 0x67452301
        self.h1 = 0xEFCDAB89
        self.h2 = 0x98BADCFE
        self.h3 = 0x10325476
        self.h4 = 0xC3D2E1F0
        self.hh = 0x00

    def update(self, msg):

        # Preprocessing
        msg = self.pad(msg, len(msg))

        for i in range(0, len(msg), 64):
            words = [0] * 80

            # Split |chunk| into sixteen 32-bit big-endian words w[i], 
            # 0 <= i <= 15
            for j in range(16):
                words[j] = struct.unpack(b">I", msg[i + j * 4:i + j * 4 + 4])[0]

            for j in range(16, 80):
                words[j] = (leftrotate((words[j - 3] ^ words[j - 8] ^ 
                 words[j - 14] ^ words[j - 16]), 1))

            # Initialize hash values for this chunk.
            a = self.h0
            b = self.h1
            c = self.h2
            d = self.h3
            e = self.h4

            for j in range(80):
                if j >= 0 and j <= 19:
                    f = d ^ (b & (c ^ d))
                    k = 0x5A827999
                elif j >= 20 and j <= 39:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif j >= 40 and j <= 59:
                    f = (b & c) ^ (b & d) ^ (c & d)
                    k = 0x8F1BBCDC
                elif j >= 60 and j < 80:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6
                else:
                    raise ValueError("Invalid index.")

                temp = (leftrotate(a, 5) + f + e + k + words[j]) % 2**32
                e = d
                d = c
                c = leftrotate(b, 30)
                b = a
                a = temp

            self.h0 = (self.h0 + a) % 2**32
            self.h1 = (self.h1 + b) % 2**32
            self.h2 = (self.h2 + c) % 2**32
            self.h3 = (self.h3 + d) % 2**32
            self.h4 = (self.h4 + e) % 2**32

        self.hh = ((self.h0 << 128) | (self.h1 << 96) | (self.h2 << 64) | 
         (self.h3 << 32) | (self.h4 & (1 << 32) - 1))

    def pad(self, msg, ml):
        mbl = ml * 8

        msg += "\x80" # Append a 1 to the bits of the message.
        msg += "\x00" * ((56 - (ml + 1) % 64) % 64)
        msg += struct.pack(b">Q", mbl)

        return msg

    def hexdigest(self):
        return format(self.hh, "032x")

    def digest(self):
        return unhexify(format(self.hh, "032x"))

    def length_extension(self, h, append):
        self.h0 = int(h[:8], 16)
        self.h1 = int(h[8:16], 16)
        self.h2 = int(h[16:24], 16)
        self.h3 = int(h[24:32], 16)
        self.h4 = int(h[32:], 16)

        self.update(append)

        return self.hexdigest()

def hmac(key, data):
    s = sha1()
    t = sha1()
    ipad = b"\x36" * 64
    opad = b"\x5C" * 64

    if len(key) < 64:
        key += b"\x00" * (64 - len(key))
    elif len(key) > 64 * 2:
        print("key > 64")
        u = sha1()
        u.update(key)
        key = u.hexdigest()
        key += b"\x00" * (64 - len(key))

    s.update(xor(key, ipad) + data)
    t.update(xor(key, opad) + s.digest())

    return t.hexdigest()
