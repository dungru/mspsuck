# -*- coding: utf-8 -*-
import binascii

from scapy.all import ARP
from scapy.all import Dot1Q
from scapy.all import Ether
from scapy.all import IP
from scapy.all import IPv6
from scapy.all import Packet
from scapy.all import TCP
from scapy.all import UDP
from scapy.all import VXLAN


def serialize(pkt):
    """
    Serialize the scapy.Packet object according to a list of traffic protocol
    headers.

    see: https://github.com/open-traffic-generator/models/tree/master/flow/packet-headers

    Args:
        pkt: a scapy.Packet object

    Returns:
        A array of traffic protocol headers. For example:

        pkt = (
            Ether(src="00:00:11:01:00:01", dst="00:00:11:02:00:01")
            / IP(src="11.1.0.101", dst="11.2.0.101")
            / TCP()
        )

        The pkt object will be serialized to:

        [
            {
                "choice": "ethernet",
                "ethernet": {
                    "dst": {"value": "00:00:11:02:00:01"},
                    "ether_type": {"choice": "value", "value": 2048},
                    "src": {"value": "00:00:11:01:00:01"},
                },
            },
            {
                "choice": "ipv4",
                "ipv4": {
                    "dont_fragment": {"choice": "value", "value": 0},
                    "dst": {"choice": "value", "value": "11.2.0.101"},
                    "fragment_offset": {"choice": "value", "value": 0},
                    "header_length": {"choice": "value", "value": None},
                    "identification": {"choice": "value", "value": 1},
                    "more_fragments": {"choice": "value", "value": 0},
                    "priority": {
                        "choice": "raw",
                        "raw": {"choice": "value", "value": 0},
                    },
                    "protocol": {"choice": "value", "value": 6},
                    "reserved": {"choice": "value", "value": 0},
                    "src": {"choice": "value", "value": "11.1.0.101"},
                    "time_to_live": {"choice": "value", "value": 64},
                    "total_length": {"choice": "value", "value": None},
                    "version": {"choice": "value", "value": 4},
                },
            },
            {
                "choice": "custom",
                "custom": {"bytes": "0014005000000000000000005002200078b20000"},
            },
        ]


    Raises:
        TypeError: An error occurred if pkt is not a scapy.Packet object.
    """
    if not isinstance(pkt, Packet):
        raise TypeError

    headers = [
        __TYPE_MAP.get(pkt.getlayer(i).__class__, __custom)(pkt.getlayer(i))
        for i in range(len(pkt.layers()))
    ]
    # pdb.set_trace()
    return headers


def __custom(pkt):
    pkt_tmp = pkt.copy()
    pkt_tmp.remove_payload()
    return {
        "choice": "custom",
        "custom": {"bytes": binascii.hexlify(bytes(pkt_tmp)).decode("utf-8")},
    }


def __ethernet(pkt):
    return {
        "choice": "ethernet",
        "ethernet": {
            "src": {"value": pkt.src},
            "dst": {"value": pkt.dst},
            "ether_type": {
                "choice": "value",
                "value": pkt.type,
            },
        },
    }


def __ipv4(pkt):
    pkt_json = {
        "choice": "ipv4",
        "ipv4": {
            "version": {
                "choice": "value",
                "value": pkt.version,
            },
            "header_length": {
                "choice": "value",
                "value": pkt.ihl,
            },
            "priority": {
                "choice": "dscp",
                "dscp": {
                    "phb": {
                        "choice": "value",
                        "value": int((pkt.tos & 0xFC) >> 2),
                    },
                    "ecn": {
                        "choice": "value",
                        "value": int((pkt.tos & 0x3)),
                    },
                },
            },
            "identification": {
                "choice": "value",
                "value": pkt.id,
            },
            "reserved": {
                "choice": "value",
                "value": 0,
            },
            "dont_fragment": {
                "choice": "value",
                "value": int("{0:02b}".format(pkt.flags.value)[0]),
            },
            "more_fragments": {
                "choice": "value",
                "value": int("{0:02b}".format(pkt.flags.value)[1]),
            },
            "fragment_offset": {
                "choice": "value",
                "value": pkt.frag,
            },
            "time_to_live": {
                "choice": "value",
                "value": pkt.ttl,
            },
            "protocol": {
                "choice": "value",
                "value": pkt.proto,
            },
            # FIXME
            # Currently, snappi_ixnetwork custom value is not supported.
            # Needed to find some way to set the chksum value.
            # "header_checksum": {
            #     "choice": "custom",
            #     "custom": pkt.chksum,
            # },
            "src": {
                "choice": "value",
                "value": pkt.src,
            },
            "dst": {
                "choice": "value",
                "value": pkt.dst,
            },
        },
    }

    if pkt.len:
        pkt_json["ipv4"].update(
            {
                "total_length": {
                    "choice": "value",
                    "value": pkt.len,
                }
            }
        )
    else:
        pkt_json["ipv4"].update({"total_length": {"choice": "auto"}})

    return pkt_json


def __ipv6(pkt):
    pkt_json = {
        "choice": "ipv6",
        "ipv6": {
            "version": {
                "choice": "value",
                "value": pkt.version,
            },
            "traffic_class": {
                "choice": "value",
                "value": pkt.tc,
            },
            "flow_label": {
                "choice": "value",
                "value": pkt.fl,
            },
            "next_header": {
                "choice": "value",
                "value": pkt.nh,
            },
            "hop_limit": {
                "choice": "value",
                "value": pkt.hlim,
            },
            "src": {
                "choice": "value",
                "value": pkt.src,
            },
            "dst": {
                "choice": "value",
                "value": pkt.dst,
            },
        },
    }

    if pkt.plen:
        pkt_json["ipv6"].update(
            {
                "payload_length": {
                    "choice": "value",
                    "value": pkt.plen,
                }
            }
        )
    else:
        pkt_json["ipv6"].update({"payload_length": {"choice": "auto"}})

    return pkt_json


def __vlan(pkt):
    pkt_json = {
        "choice": "vlan",
        "vlan": {
            "priority": {
                "choice": "value",
                "value": pkt.prio,
            },
            "cfi": {
                "choice": "value",
                "value": pkt.id,
            },
            "id": {
                "choice": "value",
                "value": pkt.vlan,
            },
        },
    }

    if pkt.type > 0:
        pkt_json["vlan"].update(
            {
                "tpid": {
                    "choice": "value",
                    "value": pkt.type,
                },
            }
        )

    return pkt_json


def __tcp(pkt):
    return {
        "choice": "tcp",
        "tcp": {
            "src_port": {"choice": "value", "value": pkt.sport},
            "dst_port": {"choice": "value", "value": pkt.dport},
            "seq_num": {"choice": "value", "value": pkt.seq},
            "ack_num": {"choice": "value", "value": pkt.ack},
            "data_offset": {"choice": "value", "value": pkt.dataofs},
            "ecn_ns": {
                "choice": "value",
                "value": int(pkt.flags.N),
            },
            "ecn_cwr": {
                "choice": "value",
                "value": int(pkt.flags.C),
            },
            "ecn_echo": {
                "choice": "value",
                "value": int(pkt.flags.E),
            },
            "ctl_urg": {
                "choice": "value",
                "value": int(pkt.flags.U),
            },
            "ctl_ack": {
                "choice": "value",
                "value": int(pkt.flags.A),
            },
            "ctl_psh": {
                "choice": "value",
                "value": int(pkt.flags.P),
            },
            "ctl_rst": {
                "choice": "value",
                "value": int(pkt.flags.R),
            },
            "ctl_syn": {
                "choice": "value",
                "value": int(pkt.flags.S),
            },
            "ctl_fin": {
                "choice": "value",
                "value": int(pkt.flags.F),
            },
            "window": {"choice": "value", "value": pkt.window},
        },
    }


def __vxlan(pkt):
    return {
        "choice": "vxlan",
        "vxlan": {
            "flags": {
                "choice": "value",
                "value": int(pkt.flags),
            },
            "reserved0": {
                "choice": "value",
                "value": pkt.reserved0,
            },
            "vni": {
                "choice": "value",
                "value": pkt.vni,
            },
            "reserved1": {
                "choice": "value",
                "value": pkt.reserved1,
            },
        },
    }


def __udp(pkt):
    return {
        "choice": "udp",
        "udp": {
            "src_port": {"choice": "value", "value": pkt.sport},
            "dst_port": {"choice": "value", "value": pkt.dport},
            "length": {"choice": "value", "value": pkt.len}
            # TODO: "length" and "checksum" <auto> gen by ixia.
        },
    }


def __arp(pkt):
    pkt_json = {
        "choice": "arp",
        "arp": {
            "hardware_type": {"choice": "value", "value": pkt.hwtype},
            "protocol_type": {"choice": "value", "value": pkt.ptype},
            "hardware_length": {
                "choice": "value",
                "value": pkt.hwlen if pkt.hwlen else 6,
            },
            "protocol_length": {
                "choice": "value",
                "value": pkt.plen if pkt.plen else 4,
            },
            "operation": {"choice": "value", "value": pkt.op},
            "sender_hardware_addr": {"choice": "value", "value": pkt.hwsrc},
            "sender_protocol_addr": {"choice": "value", "value": pkt.psrc},
            "target_hardware_addr": {"choice": "value", "value": pkt.hwdst},
            "target_protocol_addr": {"choice": "value", "value": pkt.pdst},
        },
    }
    return pkt_json


__TYPE_MAP = {
    Ether: __ethernet,
    IP: __ipv4,
    IPv6: __ipv6,
    Dot1Q: __vlan,
    TCP: __tcp,
    UDP: __udp,
    VXLAN: __vxlan,
    ARP: __arp,
}
