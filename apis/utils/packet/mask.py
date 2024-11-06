# -*- coding: utf-8 -*-
"""
Forked from https://github.com/p4lang/ptf/blob/master/src/ptf/mask.py
"""
from scapy.utils import hexdump


class Mask(object):
    def __init__(self, exp_pkt, ignore_extra_bytes=False):
        self.exp_pkt = exp_pkt
        self.size = len(exp_pkt)
        self.mask = [0xFF] * self.size
        self.ignore_extra_bytes = ignore_extra_bytes

    def set_do_not_care(self, offset, bitwidth):
        # a very naive but simple method
        # we do it bit by bit :)
        for idx in range(offset, offset + bitwidth):
            offsetB = idx // 8
            offsetb = idx % 8
            self.mask[offsetB] = self.mask[offsetB] & (~(1 << (7 - offsetb)))

    def set_do_not_care_packet(self, hdr_type, field_name):
        # Unknown header type
        if hdr_type not in self.exp_pkt:
            return

        try:
            fields_desc = hdr_type.fields_desc
        except AttributeError:
            return

        hdr_offset = self.size - len(self.exp_pkt[hdr_type])
        offset = 0
        bitwidth = 0
        for f in fields_desc:
            try:
                bits = f.size
            except AttributeError:
                bits = 8 * f.sz

            if f.name == field_name:
                bitwidth = bits
                break
            else:
                offset += bits

        self.set_do_not_care(hdr_offset * 8 + offset, bitwidth)

    def set_ignore_extra_bytes(self):
        self.ignore_extra_bytes = True

    def pkt_match(self, pkt):
        # just to be on the safe side
        pkt = bytearray(bytes(pkt))

        # we fail if we don't match on sizes, or if ignore_extra_bytes is set,
        # fail if we have not received at least size bytes
        if (not self.ignore_extra_bytes and len(pkt) != self.size) or len(
            pkt
        ) < self.size:
            return False

        exp_pkt = bytearray(bytes(self.exp_pkt))
        for i in range(self.size):
            if (exp_pkt[i] & self.mask[i]) != (pkt[i] & self.mask[i]):
                return False

        return True

    def __str__(self):
        buf = list()
        buf.append("exp_pkt:")
        buf.append(hexdump(self.exp_pkt, dump=True))

        buf.append("mask:")
        for i in range(0, len(self.mask), 16):
            buf.append(
                f"{i:04x}  "
                f"{' '.join('%02x' % x for x in self.mask[i:i + 16])}"
            )

        return "\n".join(buf)

    def __repr__(self):
        return str(self)


def __utest():
    from scapy.all import Ether, IP, TCP

    p = Ether() / IP() / TCP()
    m = Mask(p)
    assert m.pkt_match(p)
    p1 = Ether() / IP() / TCP(sport=97)
    assert not m.pkt_match(p1)
    m.set_do_not_care_packet(TCP, "sport")
    assert not m.pkt_match(p1)
    m.set_do_not_care_packet(TCP, "chksum")
    assert m.pkt_match(p1)
    exp_pkt = "\x01\x02\x03\x04\x05\x06"
    pkt = "\x01\x00\x00\x04\x05\x06\x07\x08"
    m1 = Mask(exp_pkt.encode(), ignore_extra_bytes=True)
    m1.set_do_not_care(8, 16)
    assert m1.pkt_match(pkt.encode())


if __name__ == "__main__":
    __utest()
