# -*- coding: utf-8 -*-
import sys

try:
    from scapy.fields import BitField
    from scapy.fields import BitEnumField
    from scapy.fields import IP6Field
    from scapy.fields import IntField
    from scapy.fields import IntEnumField
    from scapy.fields import IPField
    from scapy.fields import MultipleTypeField
    from scapy.fields import PacketLenField
    from scapy.fields import PacketListField
    from scapy.fields import FieldListField
    from scapy.fields import StrField
    from scapy.fields import StrLenField
    from scapy.fields import PadField
    from scapy.fields import MACField
    from scapy.layers.inet import UDP
    from scapy.layers.netflow import NetflowHeader
    from scapy.packet import Packet
    from scapy.packet import bind_layers
    from scapy.packet import split_bottom_up
except ImportError:
    sys.exit("Need to install scapy for packet parsing")


class UnknowSample(Packet):
    name = "UnknowSample"
    fields_desc = [
        BitField("enterprise", 0, 20),
        BitField("format", 0, 12),
        StrLenField("data", "", length_from=lambda p: len(p) - 8),
    ]


class SflowRawPacketHeader(Packet):
    name = "SflowRawPacketHeader"
    fields_desc = [
        IntField("header_protocol", 0),
        IntField("frame_length", 0),
        IntField("stripped", 0),
        IntField("header_size", 0),
        StrLenField("data", "", length_from=lambda pkt: pkt.header_size),
    ]


class SflowEthernetFrameData(Packet):
    name = "SflowEthernetFrameData"
    fields_desc = [
        IntField("length", 0),
        PadField(MACField("src_mac", "00:00:00:00:00:00"), 6, padwith=b"\x00"),
        PadField(MACField("dst_mac", "00:00:00:00:00:00"), 6, padwith=b"\x00"),
        IntField("type", 0),
    ]


class SflowIpv4Data(Packet):
    name = "SflowIpv4Data"
    fields_desc = [
        IntField("ip_packet_length", 0),
        BitEnumField(
            "ip_protocol",
            0,
            32,
            {
                6: "6 tcp",
                17: "17 udp",
            },
        ),
        IPField("src_ip", "127.0.0.1"),
        IPField("dest_ip", "127.0.0.1"),
        IntField("src_port", 0),
        IntField("dest_port", 0),
        IntField("tcp_flags", 0),
        IntField("type_of_service", 0),
    ]


class SflowIpv6Data(Packet):
    name = "SflowIpv6Data"
    fields_desc = [
        IntField("ip_packet_length", 0),
        BitEnumField(
            "ip_next_header",
            0,
            32,
            {
                6: "6 tcp",
                17: "17 udp",
            },
        ),
        IP6Field("src_ipv6", "::"),
        IP6Field("dest_ipv6", "::"),
        IntField("src_port", 0),
        IntField("dest_port", 0),
        IntField("tcp_flags", 0),
        IntField("type_of_service", 0),
    ]


class SflowExtendedSwitchData(Packet):
    name = "SflowExtendedSwitchData"
    fields_desc = [
        IntField("src_vlan", 0),
        IntField("src_priority", 0),
        IntField("dest_vlan", 0),
        IntField("dest_prority", 0),
    ]


class SflowExtendedRouterData(Packet):
    name = "SflowExtendedRouterData"
    fields_desc = [
        IntField("ip_version", 0),
        MultipleTypeField(
            [
                (
                    IPField("next_hop_router", "127.0.0.1"),
                    lambda pkt: pkt.ip_version == 1,
                ),
                (
                    IP6Field("next_hop_router", "::"),
                    lambda pkt: pkt.ip_version == 2,
                ),
            ],
            StrField("next_hop_router", ""),
        ),
        IntField("src_mask_len", 0),
        IntField("dest_mask_len", 0),
    ]


class _AS_Path(Packet):
    name = "as_path"
    fields_desc = [
        BitEnumField(
            "as path segment type",
            0,
            32,
            {
                1: "1=set / unordered",
                2: "2=sequence / ordered",
            },
        ),
        IntField("length_as_list", 0),
        FieldListField(
            "as_number_lists",
            [],
            IntField("as_number", 0),
            count_from=lambda pkt: pkt.length_as_list,
        ),
    ]


class SflowExtendedGatewayData(Packet):
    name = "SflowExtendedGatewayData"
    fields_desc = [
        IntField("ip_version", 0),
        MultipleTypeField(
            [
                (
                    IPField("next_hop_router", "127.0.0.1"),
                    lambda pkt: pkt.ip_version == 1,
                ),
                (
                    IP6Field("next_hop_router", "::"),
                    lambda pkt: pkt.ip_version == 2,
                ),
            ],
            StrField("next_hop_router", ""),
        ),
        IntField("as_number_route", 0),
        IntField("as_number_source", 0),
        IntField("as_number_source_peer", 0),
        IntField("dest_as_paths_number", 0),
        PacketListField(
            "dest_as_paths_lists",
            [],
            _AS_Path,
            count_from=lambda p: p.dest_as_paths_number,
        ),
        IntField("length_communities_list", 0),
        FieldListField(
            "communities_list",
            [],
            IntField("communities", 0),
            count_from=lambda p: p.length_communities_list,
        ),
        IntField("LocalPref", 0),
    ]


class SflowExtendedUserData(Packet):
    name = "SflowExtendedUserData"
    fields_desc = [
        IntField("source_charset", 0),
        IntField("length_source_user_string", 0),
        StrLenField(
            "source_user_string",
            "",
            length_from=lambda p: p.length_source_user_string,
        ),
        IntField("destination_charset", 0),
        IntField("length_destination_user_string", 0),
        StrLenField(
            "destination_user_string",
            "",
            length_from=lambda p: p.length_destination_user_string,
        ),
    ]


class SflowExtendedUrlData(Packet):
    name = "SflowExtendedUrlData"
    fields_desc = [
        IntField("direction", 0),
        IntField("length_url", 0),
        StrLenField("string_url", "", length_from=lambda p: p.length_url),
        IntField("length_host", 0),
        StrLenField("string_host", "", length_from=lambda p: p.length_host),
    ]


class SflowExtendedMplsData(Packet):
    name = "SflowExtendedMplsData"
    fields_desc = [
        IntField("ip_version", 0),
        MultipleTypeField(
            [
                (
                    IPField("next_hop_router", "127.0.0.1"),
                    lambda pkt: pkt.ip_version == 1,
                ),
                (
                    IP6Field("next_hop_router", "::"),
                    lambda pkt: pkt.ip_version == 2,
                ),
            ],
            StrField("next_hop_router", ""),
        ),
        IntField("in_label_stack_number", 0),
        FieldListField(
            "in_label_stacks",
            [],
            IntField("in_label_stack", 0),
            count_from=lambda p: p.in_label_stack_number,
        ),
        IntField("out_label_stack_number", 0),
        FieldListField(
            "out_label_stacks",
            [],
            IntField("out_label_stack", 0),
            count_from=lambda p: p.out_label_stack_number,
        ),
    ]


class SflowExtendedNatData(Packet):
    name = "SflowExtendedNatData"
    fields_desc = [
        IntField("version_source_address", 0),
        MultipleTypeField(
            [
                (
                    IPField("source_address", "127.0.0.1"),
                    lambda pkt: pkt.version_source_address == 1,
                ),
                (
                    IP6Field("source_address", "::"),
                    lambda pkt: pkt.version_source_address == 2,
                ),
            ],
            StrField("source_address", ""),
        ),
        IntField("version_destination_address", 0),
        MultipleTypeField(
            [
                (
                    IPField("destination_address", "127.0.0.1"),
                    lambda pkt: pkt.version_destination_address == 1,
                ),
                (
                    IP6Field("destination_address", "::"),
                    lambda pkt: pkt.version_destination_address == 2,
                ),
            ],
            StrField("destination_address", ""),
        ),
    ]


class SflowExtendedMplsTunnel(Packet):
    name = "SflowExtendedMplsTunnel"
    fields_desc = [
        IntField("length_tunnel_name", 0),
        StrLenField(
            "tunnel_name", "", length_from=lambda p: p.length_tunnel_name
        ),
        IntField("tunnel_id", 0),
        IntField("tunnel_cos_value", 0),
    ]


class SflowExtendedMplsVc(Packet):
    name = "SflowExtendedMplsVc"
    fields_desc = [
        IntField("length_vc_instance_name", 0),
        StrLenField(
            "vc_instance_name",
            "",
            length_from=lambda p: p.length_vc_instance_name,
        ),
        IntField("id", 0),
        IntField("vc_label_cos_value", 0),
    ]


class SflowExtendedMplsFec(Packet):
    name = "SflowExtendedMplsFec"
    fields_desc = [
        IntField("length_mplsFTNDescr", 0),
        StrLenField(
            "mplsFTNDescr", "", length_from=lambda p: p.length_mplsFTNDescr
        ),
        IntField("mplsFTNMask", 0),
    ]


class SflowExtendedMplsLvpFec(Packet):
    name = "SflowExtendedMplsLvpFec"
    fields_desc = [
        IntField("length_mplsFecAddrPrefixLength", 0),
    ]


class SflowExtendedVlanTunnel(Packet):
    name = "SflowExtendedVlanTunnel"
    fields_desc = [
        IntField("layer_stack_number", 0),
        FieldListField(
            "layer_stack",
            [],
            IntField("layer_stack", 0),
            count_from=lambda p: p.layer_stack_number,
        ),
    ]


class SflowFlowRecord(Packet):
    name = "SflowFlowRecord"
    fields_desc = [
        BitField("enterprise", 0, 20),
        BitEnumField(
            "format",
            0,
            12,
            {
                1: "1 (Raw Packet Header)",
                2: "2 (Ethernet Frame Data)",
                3: "3 (IPv4 Data)",
                4: "4 (IPv6 Data)",
                1001: "1001 (Extended Switch Data)",
                1002: "1002 (Extended Router Data)",
                1003: "1003 (Extended Gateway Data)",  # Notes: There is a part called AS Path
                1004: "1004 (Extended User Data)",
                1005: "1005 (Extended Url Data)",
                1006: "1006 (Extended MPLS Data)",
                1007: "1007 (Extended NAT Data)",
                1008: "1008 (Extended MPLS Tunnel)",
                1009: "1009 (Extended MPLS VC)",
                1010: "1010 (Extended MPLS FEC)",
                1011: "1011 (Extended MPLS LVP FEC)",
                1012: "1012 (Extended VLAN tunnel)",
            },
        ),
        IntField("length", 0),
        MultipleTypeField(
            [
                (
                    PacketLenField(
                        "data",
                        "",
                        SflowRawPacketHeader,
                        length_from=lambda pkt: pkt.length,
                    ),
                    lambda pkt: pkt.format == 1,
                ),
                (
                    PacketLenField(
                        "data",
                        "",
                        SflowEthernetFrameData,
                        length_from=lambda pkt: pkt.length,
                    ),
                    lambda pkt: pkt.format == 2,
                ),
                (
                    PacketLenField(
                        "data",
                        "",
                        SflowIpv4Data,
                        length_from=lambda pkt: pkt.length,
                    ),
                    lambda pkt: pkt.format == 3,
                ),
                (
                    PacketLenField(
                        "data",
                        "",
                        SflowIpv6Data,
                        length_from=lambda pkt: pkt.length,
                    ),
                    lambda pkt: pkt.format == 4,
                ),
                (
                    PacketLenField(
                        "data",
                        "",
                        SflowExtendedSwitchData,
                        length_from=lambda pkt: pkt.length,
                    ),
                    lambda pkt: pkt.format == 1001,
                ),
                (
                    PacketLenField(
                        "data",
                        "",
                        SflowExtendedRouterData,
                        length_from=lambda pkt: pkt.length,
                    ),
                    lambda pkt: pkt.format == 1002,
                ),
                (
                    PacketLenField(
                        "data",
                        "",
                        SflowExtendedGatewayData,
                        length_from=lambda pkt: pkt.length,
                    ),
                    lambda pkt: pkt.format == 1003,
                ),
                (
                    PacketLenField(
                        "data",
                        "",
                        SflowExtendedUserData,
                        length_from=lambda pkt: pkt.length,
                    ),
                    lambda pkt: pkt.format == 1004,
                ),
                (
                    PacketLenField(
                        "data",
                        "",
                        SflowExtendedUrlData,
                        length_from=lambda pkt: pkt.length,
                    ),
                    lambda pkt: pkt.format == 1005,
                ),
                (
                    PacketLenField(
                        "data",
                        "",
                        SflowExtendedMplsData,
                        length_from=lambda pkt: pkt.length,
                    ),
                    lambda pkt: pkt.format == 1006,
                ),
                (
                    PacketLenField(
                        "data",
                        "",
                        SflowExtendedNatData,
                        length_from=lambda pkt: pkt.length,
                    ),
                    lambda pkt: pkt.format == 1007,
                ),
                (
                    PacketLenField(
                        "data",
                        "",
                        SflowExtendedMplsTunnel,
                        length_from=lambda pkt: pkt.length,
                    ),
                    lambda pkt: pkt.format == 1008,
                ),
                (
                    PacketLenField(
                        "data",
                        "",
                        SflowExtendedMplsVc,
                        length_from=lambda pkt: pkt.length,
                    ),
                    lambda pkt: pkt.format == 1009,
                ),
                (
                    PacketLenField(
                        "data",
                        "",
                        SflowExtendedMplsFec,
                        length_from=lambda pkt: pkt.length,
                    ),
                    lambda pkt: pkt.format == 1010,
                ),
                (
                    PacketLenField(
                        "data",
                        "",
                        SflowExtendedMplsLvpFec,
                        length_from=lambda pkt: pkt.length,
                    ),
                    lambda pkt: pkt.format == 1011,
                ),
                (
                    PacketLenField(
                        "data",
                        "",
                        SflowExtendedVlanTunnel,
                        length_from=lambda pkt: pkt.length,
                    ),
                    lambda pkt: pkt.format == 1012,
                ),
            ],
            PacketLenField(
                "data", "", UnknowSample, length_from=lambda pkt: pkt.length
            ),
        ),
    ]

    def extract_padding(self, p):
        return "", p


class SflowGenericInterfaceCounters(Packet):
    name = "SflowGenericInterfaceCounters"
    fields_desc = [
        IntField("ifIndex", 0),
        IntField("ifType", 0),
        BitField("ifSpeed", 0, 64),
        BitEnumField(
            "ifDirection",
            0,
            32,
            {
                0: "unknown",
                1: "full-duplex",
                2: "half-duplex",
                3: "in",
                4: "out",
            },
        ),
        BitEnumField(
            "ifStatus",
            0,
            32,
            {
                0: "00 ifAdminStatus=down,ifOperStatus=down",
                1: "01 ifAdminStatus=down,ifOperStatus=up",
                2: "10 ifAdminStatus=up,ifOperStatus=down",
                3: "11 ifAdminStatus=up,ifOperStatus=up",
            },
        ),
        BitField("ifInOctets", 0, 64),
        IntField("ifInUcastPkts", 0),
        IntField("ifInMulticastPkts", 0),
        IntField("ifInBroadcastPkts", 0),
        IntField("ifInDiscards", 0),
        IntField("ifInErrors", 0),
        IntField("ifInUnknownProtos", 0),
        BitField("ifOutOctets", 0, 64),
        IntField("ifOutUcastPkts", 0),
        IntField("ifOutMulticastPkts", 0),
        IntField("ifOutBroadcastPkts", 0),
        IntField("ifOutDiscards", 0),
        IntField("ifOutErrors", 0),
        IntField("ifPromiscuousMode", 0),
    ]


class SflowEthernetInterfaceCounters(Packet):
    name = "SflowEthernetInterfaceCounters"
    fields_desc = [
        IntField("dot3StatsAlignmentErrors", 0),
        IntField("dot3StatsFCSErrors", 0),
        IntField("dot3StatsSingleCollisionFrames", 0),
        IntField("dot3StatsMultipleCollisionFrames", 0),
        IntField("dot3StatsSQETestErrors", 0),
        IntField("dot3StatsDeferredTransmissions", 0),
        IntField("dot3StatsLateCollisions", 0),
        IntField("dot3StatsExcessiveCollisions", 0),
        IntField("dot3StatsInternalMacTransmitErrors", 0),
        IntField("dot3StatsCarrierSenseErrors", 0),
        IntField("dot3StatsFrameTooLongs", 0),
        IntField("dot3StatsInternalMacReceiveErrors", 0),
        IntField("dot3StatsSymbolErrors", 0),
    ]


class SflowTokenRingCounters(Packet):
    name = "SflowTokenRingCounters"
    fields_desc = [
        IntField("dot5StatsLineErrors", 0),
        IntField("dot5StatsBurstErrors", 0),
        IntField("dot5StatsACErrors", 0),
        IntField("dot5StatsAbortTransErrors", 0),
        IntField("dot5StatsInternalErrors", 0),
        IntField("dot5StatsLostFrameErrors", 0),
        IntField("dot5StatsReceiveCongestions", 0),
        IntField("dot5StatsFrameCopiedErrors", 0),
        IntField("dot5StatsTokenErrors", 0),
        IntField("dot5StatsSoftErrors", 0),
        IntField("dot5StatsHardErrors", 0),
        IntField("dot5StatsSignalLoss", 0),
        IntField("dot5StatsTransmitBeacons", 0),
        IntField("dot5StatsRecoverys", 0),
        IntField("dot5StatsLobeWires", 0),
        IntField("dot5StatsRemoves", 0),
        IntField("dot5StatsSingles", 0),
        IntField("dot5StatsFreqErrors", 0),
    ]


class Sflow100BaseVGInterfaceCounters(Packet):
    name = "Sflow100BaseVGInterfaceCounters"
    fields_desc = [
        IntField("dot12InHighPriorityFrames", 0),
        BitField("dot12InHighPriorityOctets", 0, 64),
        IntField("dot12InNormPriorityFrames", 0),
        BitField("dot12InNormPriorityOctets", 0, 64),
        IntField("dot12InIPMErrors", 0),
        IntField("dot12InOversizeFrameErrors", 0),
        IntField("dot12InDataErrors", 0),
        IntField("dot12InNullAddressedFrames", 0),
        IntField("dot12OutHighPriorityFrames", 0),
        BitField("dot12OutHighPriorityOctets", 0, 64),
        IntField("dot12TransitionIntoTrainings", 0),
        BitField("dot12HCInHighPriorityOctets", 0, 64),
        BitField("dot12HCInNormPriorityOctets", 0, 64),
        BitField("dot12HCOutHighPriorityOctets", 0, 64),
    ]


class SflowVlanCounters(Packet):
    name = "SflowVLANCounters"
    fields_desc = [
        IntField("vlan_id", 0),
        BitField("octets", 0, 64),
        IntField("ucastPkts", 0),
        IntField("multicastPkts", 0),
        IntField("broadcastPkts", 0),
        IntField("discards", 0),
    ]


class SflowProcessorInformation(Packet):
    name = "SflowProcessorInformation"
    fields_desc = [
        IntField("cpu_percentage_5s", 0),
        IntField("cpu_percentage_1m", 0),
        IntField("cpu_percentage_5m", 0),
        BitField("total_memory", 0, 64),
        BitField("free_memory", 0, 64),
    ]


class SflowCounterRecord(Packet):
    name = "SflowCounterRecord"
    fields_desc = [
        BitField("enterprise", 0, 20),
        BitEnumField(
            "format",
            0,
            12,
            {
                1: "1 (Generic Interface Counters)",
                2: "2 (Ethernet Interface Counters)",
                3: "3 (Token Ring Counters)",
                4: "4 (100 BaseVG Interface Counters)",
                5: "5 (VLAN Counters)",
                1001: "1001 (Processor Information)",
            },
        ),
        IntField("length", 0),
        MultipleTypeField(
            [
                (
                    PacketLenField(
                        "data",
                        "",
                        SflowGenericInterfaceCounters,
                        length_from=lambda pkt: pkt.length,
                    ),
                    lambda pkt: pkt.format == 1,
                ),
                (
                    PacketLenField(
                        "data",
                        "",
                        SflowEthernetInterfaceCounters,
                        length_from=lambda pkt: pkt.length,
                    ),
                    lambda pkt: pkt.format == 2,
                ),
                (
                    PacketLenField(
                        "data",
                        "",
                        SflowTokenRingCounters,
                        length_from=lambda pkt: pkt.length,
                    ),
                    lambda pkt: pkt.format == 3,
                ),
                (
                    PacketLenField(
                        "data",
                        "",
                        Sflow100BaseVGInterfaceCounters,
                        length_from=lambda pkt: pkt.length,
                    ),
                    lambda pkt: pkt.format == 4,
                ),
                (
                    PacketLenField(
                        "data",
                        "",
                        SflowVlanCounters,
                        length_from=lambda pkt: pkt.length,
                    ),
                    lambda pkt: pkt.format == 5,
                ),
                (
                    PacketLenField(
                        "data",
                        "",
                        SflowProcessorInformation,
                        length_from=lambda pkt: pkt.length,
                    ),
                    lambda pkt: pkt.format == 1001,
                ),
            ],
            PacketLenField(
                "data", "", UnknowSample, length_from=lambda pkt: pkt.length
            ),
        ),
    ]

    def extract_padding(self, p):
        return "", p


class FlowSample(Packet):  # enterprise = 0, format = 1
    name = "FlowSample"

    fields_desc = [
        IntField("sequence_number", 0),
        BitEnumField(
            "source_id_type",
            0,
            8,
            {
                0: "0 (ifIndex)",
                1: "1 (smonVlanDataSource)",
                2: "2 (entPhysicalEntry)",
            },
        ),
        BitField("source_id_index", 0, 24),
        IntField("sampling_rate", 0),
        IntField(
            "sample_pool", 0
        ),  # total number of packets that could have been sampled
        IntField("drops", 0),  # packets dropped due to a lack of resources
        IntField(
            "input", 0
        ),  # SNMP ifIndex of input interface, 0 if not known
        IntField(
            "output", 0
        ),  # SNMP ifIndex of output interface, 0 if not known
        IntField("number_of_records", 0),
        PacketListField(
            "record",
            [],
            SflowFlowRecord,
            count_from=lambda p: p.number_of_records,
        ),
    ]


class CounterSample(Packet):  # enterprise = 0, format = 2
    name = "CounterSample"
    fields_desc = [
        IntField("sequence_number", 0),
        BitEnumField(
            "source_id_type",
            0,
            8,
            {
                0: "0 (ifIndex)",
                1: "1 (smonVlanDataSource)",
                2: "2 (entPhysicalEntry)",
            },
        ),
        BitField("source_id_index", 0, 24),
        IntField("number_of_records", 0),
        PacketListField(
            "record",
            [],
            SflowCounterRecord,
            count_from=lambda p: p.number_of_records,
        ),
    ]


class ExpandedFlowSample(Packet):  # enterprise = 0, format = 3
    name = "ExpandedFlowSample"
    fields_desc = [
        IntField("sequence_number", 0),
        IntField("source_id_type", 0),
        IntField("source_id_index", 0),
        IntField("sampling_rate", 0),
        IntField(
            "sample_pool", 0
        ),  # total number of packets that could have been sampled
        IntField("drops", 0),  # packets dropped due to a lack of resources
        IntField("input_interface_format", 0),
        IntField("input_interface_value", 0),
        IntField("output_interface_format", 0),
        IntField("output_interface_value", 0),
        IntField("number_of_records", 0),
        PacketListField(
            "record",
            [],
            SflowFlowRecord,
            count_from=lambda p: p.number_of_records,
        ),
    ]


class ExpandedCounterSample(Packet):  # enterprise = 0, format = 4
    name = "ExpandedCounterSample"
    fields_desc = [
        IntField("sequence_number", 0),
        IntField("source_id_type", 0),
        IntField("source_id_index", 0),
        IntField("number_of_records", 0),
        PacketListField(
            "record",
            [],
            SflowCounterRecord,
            count_from=lambda p: p.number_of_records,
        ),
    ]


class SflowSampledata(Packet):
    name = "SflowSampledata"
    fields_desc = [
        BitField("enterprise", 0, 20),
        BitEnumField(
            "format",
            0,
            12,
            {
                1: "1 (Flow Sample)",
                2: "2 (Counter Sample)",
                3: "3 (Expanded Flow Sample)",
                4: "4 (Expanded Counter Sample)",
            },
        ),
        IntField("length", 0),
        MultipleTypeField(
            [
                (
                    PacketLenField(
                        "data",
                        "",
                        FlowSample,
                        length_from=lambda pkt: pkt.length,
                    ),
                    lambda pkt: pkt.format == 1,
                ),
                (
                    PacketLenField(
                        "data",
                        "",
                        CounterSample,
                        length_from=lambda pkt: pkt.length,
                    ),
                    lambda pkt: pkt.format == 2,
                ),
                (
                    PacketLenField(
                        "data",
                        "",
                        ExpandedFlowSample,
                        length_from=lambda pkt: pkt.length,
                    ),
                    lambda pkt: pkt.format == 3,
                ),
                (
                    PacketLenField(
                        "data",
                        "",
                        ExpandedCounterSample,
                        length_from=lambda pkt: pkt.length,
                    ),
                    lambda pkt: pkt.format == 4,
                ),
            ],
            PacketLenField(
                "data", "", UnknowSample, length_from=lambda pkt: pkt.length
            ),
        ),
    ]

    def extract_padding(self, p):
        return "", p


class SflowV5(Packet):
    name = "SflowV5"
    fields_desc = [
        IntField("version", 0),
        IntEnumField("agent_ip_version", 1, {1: "1 (v4)", 2: "2 (v6)"}),
        MultipleTypeField(
            [
                (
                    IPField("agent_ip", "192.168.0.1"),
                    lambda pkt: pkt.agent_ip_version == 1,
                ),
                (
                    IP6Field("agent_ip", "::"),
                    lambda pkt: pkt.agent_ip_version == 2,
                ),
            ],
            StrField("agent_ip", ""),
        ),
        IntField("sub_agent_id", 0),
        IntField("datagram_seq_num", 0),
        IntField("switch_uptime_in_ms", 0),
        IntField("number_of_samples", 0),
        PacketListField(
            "samples",
            [],
            SflowSampledata,
            count_from=lambda p: p.number_of_samples,
        ),
    ]


split_bottom_up(
    UDP, NetflowHeader, dport=6343
)  # Unbind NetflowHeader before to binding SflowV5

bind_layers(UDP, SflowV5, dport=6343)
