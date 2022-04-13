# coding: utf-8
# Created on 07.05.2021
# Copyright © 2020-2021 Nick Krylov.
# SPDX-License-Identifier: GPL-3.0-or-later

import struct
import logging
from . import utils

logger = logging.getLogger()


class TransportBase:

    def connection_made(self, transport):
        self.transport = transport

    def connection_lost(self, exc):
        self.on_connection_lost(exc)

    def on_connection_lost(self, exc):
        pass


# SSL/TCP variant
class FramedTransportMixin(TransportBase):
    CMD = 1
    PACKET = 2
    ESPT = 4
    TLS = 0
    hdr = struct.Struct("!II")
    tls_hdr = struct.Struct("!BHH")

    @classmethod
    def tls_len(cls, data):
        hdr = cls.tls_hdr.unpack_from(data[:cls.tls_hdr.size])
        return hdr[-1]

    def __init__(self):

        self._nbytes = 0
        self._dt = None
        self._bytes = bytes()

    def data_received(self, data):
        if not data:
            return

        first_char = data[0]

        def read_tls_block(data):
            self._dt = self.TLS
            tls_len = self.tls_len(data)
            sz = self.tls_hdr.size + tls_len
            self._nbytes = sz
            self._bytes = data[:sz]
            return data[sz:]

        while data:
            if self._nbytes == 0:
                if data.find(b"HTTP") > 0:
                    return
                first_char = data[0]
                if first_char != 0:
                    data = read_tls_block(data)

                else:
                    self._nbytes , self._dt = self.hdr.unpack_from(data[:self.hdr.size])
                    nextblock = self._nbytes + self.hdr.size
                    self._bytes += data[self.hdr.size:nextblock]
                    data = data[nextblock:]
            else:

                nread = len(self._bytes)
                if self._dt == self.TLS:
                    data = read_tls_block(data)
                else:
                    rest = self._nbytes - nread
                    self._bytes += data[:rest]
                    data = data[rest:]

            if self._nbytes == len(self._bytes):
                self.process_incoming(self._bytes, self._dt)
                self._nbytes = 0
                self._bytes = bytes()

    def send_data(self, data, dtype):
        data = utils.as_bytes(data)
        dlen = len(data)
        if dtype == self.TLS:
            self.transport.write(data)
        else:
            hdr = self.hdr.pack(dlen, dtype)
            self.transport.write(hdr)
            self.transport.write(data)

    def send_packet(self, data):
        self.send_data(data, self.PACKET)

    def send_cmd(self, data):
        self.send_data(data, self.CMD)

    def send_tls(self, data):
        self.send_data(data, self.TLS)
