# coding: utf-8
# Created on 02.12.2020
# Copyright © 2020-2021 Nick Krylov.
# SPDX-License-Identifier: GPL-3.0-or-later

# Simple PKCS1-V1_5-ENCRYPT implementation with CP modifications
# Following funcs borrowed from pycrypto, which is in "public domain".

import struct


def b(s):
    return s.encode("latin-1")  # utf-8 would cause some side-effects we don't want


def bytes_to_long(s):
    """bytes_to_long(string) : long
    Convert a byte string to a long integer.

    This is (essentially) the inverse of long_to_bytes().
    """
    acc = 0
    unpack = struct.unpack
    length = len(s)
    if length % 4:
        extra = (4 - length % 4)
        s = b('\000') * extra + s
        length = length + extra
    for i in range(0, length, 4):
        acc = (acc << 32) + unpack('>I', s[i:i + 4])[0]
    return acc


def long_to_bytes(n):
    """long_to_bytes(n:long, blocksize:int) : string
    Convert a long integer to a byte string.

    If optional blocksize is given and greater than zero, pad the front of the
    byte string with binary zeros so that the length is a multiple of
    blocksize.
    """
    # after much testing, this algorithm was deemed to be the fastest
    s = b('')
    n = int(n)
    pack = struct.pack
    while n > 0:
        s = pack('>I', n & 0xffffffff) + s
        n = n >> 32
    # strip off leading zeros
    for i in range(len(s)):
        if s[i] != b('\000')[0]:
            break
    else:
        # only happens when n == 0
        s = b('\000')
        i = 0
    s = s[i:]

    return s


def ceil_div(n, d):
    """Return ceil(n/d), that is, the smallest integer r such that r*d >= n"""

    if d == 0:
        raise ZeroDivisionError()
    if (n < 0) or (d < 0):
        raise ValueError("Non positive values")
    r, q = divmod(n, d)
    if (n != 0) and (q != 0):
        r += 1
    return r


def number_size (N):
    """size(N:long) : int
    Returns the size of the number N in bits.
    """
    bits = 0
    while N >> bits:
        bits += 1
    return bits


def b_ord (x):
        return x


# https://simple.wikipedia.org/wiki/RSA_algorithm
class RSADec(object):

    def __init__(self, n, d):
        self._d = d
        self._n = n

    def _rsa_decrypt(self, m):
        intm = bytes_to_long(m)
        encm = pow(intm, self._d, self._n)
        return long_to_bytes(encm)

    def decrypt(self, msg):
        lst = []
        for i in range(0, len(msg), 2):
            lst += [int(msg[i:i + 2], 16)]
        lst = bytes(reversed(lst))
        plaintxt = self._rsa_decrypt(lst)
        pos = plaintxt[:-1].rfind(b'\x00')
        if pos:
            return plaintxt[pos + 1:-1]


class RSAEnc(object):

    def __init__(self, n, e, testing=False):
        self._n = n
        self._e = e
        self._testing = testing

    def _rsa_encrypt(self, m):
        intm = bytes_to_long(m)
        encm = pow(intm, self._e, self._n)
        return long_to_bytes(encm)

    def encrypt(self, plaintxt):
        x = self._pad(plaintxt)
        e = self._rsa_encrypt (x)
        e = ''.join ('%02x' % b_ord (c) for c in reversed (e))
        return e

    # PKCS1-V1_5
    def _pad(self, txt):
        import secrets
        # Layout is \x0 \x2 <rnd bytes!=0> \x0 txt \x0
        nbits = number_size(self._n)
        nbytes = ceil_div(nbits, 8)
        btxt = txt.encode ('utf-8')
        nrng = nbytes - (2 + 2 + len(btxt))
        rngbytes = b''
        if self._testing:
            rngbytes = b'\xff' * nrng
        else:
            valid_bytes = range(1, 255)
            for _ in range(nrng):
                rngbytes += bytes([secrets.choice(valid_bytes)])
        tp = b'\1' if self._testing else b'\2'
        ret = b"\x00" + tp + rngbytes + b"\x00" + btxt + b"\x00"
        return ret
