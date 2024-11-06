# -*- coding: utf-8 -*-
import re

from scapy.all import Packet

from apis.traffic_generator.packet import serialize
from apis.utils import AttrDict


_FLOW_NAME_RE = re.compile(r"^[\w]+$")


class Flow(AttrDict):
    """
    A high level data plane traffic flow.
    see: https://github.com/open-traffic-generator/models/tree/master/flow

    Typical usage example:

    from scapy.all import Ether, IP, TCP

    flw = Flow(
        tx_rx=DeviceTxRx(
            tx_names=["dev1"], rx_names=["dev2"]
        ),
        packet=(
            Ether(src="00:00:11:01:00:01", dst="00:00:11:02:00:01")
            / IP(src="11.1.0.101", dst="11.2.0.101")
            / TCP()
        ),
        size=FixedSize(128),
        rate=Percentage(1),
        duration=FixedPackets(5),
    )
    """

    def __init__(
        self,
        name,
        tx_rx,
        packet=None,
        size=None,
        rate=None,
        duration=None,
        metrics=None,
    ):
        super().__init__(name=name, tx_rx=tx_rx)
        if packet:
            self.update(packet=packet)
        if size:
            self.update(size=size)
        if rate:
            self.update(rate=rate)
        if duration:
            self.update(duration=duration)
        if metrics:
            self.update(metrics=metrics)
        else:
            # enables flow metrics by default
            self.update(metrics=Metrics(enable=True, loss=True))

    def __setitem__(self, key, value):
        if isinstance(value, Packet):
            value = serialize(value)

        if key == "name" and not _FLOW_NAME_RE.match(value):
            raise NameError(
                f"flow name '{value}' is not valid, "
                "only accepts `[a-zA-Z0-9_]` characters"
            )

        super().__setitem__(key, value)

    def update(self, *args, **kwargs):
        for k, v in dict(*args, **kwargs).items():
            self[k] = v


class PortTxRx(AttrDict):
    """Flow.tx_rx"""

    def __init__(self, tx_name, rx_name):
        super().__init__(
            choice="port", port=dict(tx_name=tx_name, rx_name=rx_name)
        )


class DeviceTxRx(AttrDict):
    """Flow.tx_rx"""

    def __init__(self, tx_names, rx_names, mode="mesh"):
        super().__init__(
            choice="device",
            device=dict(tx_names=tx_names, rx_names=rx_names, mode=mode),
        )


class FixedSize(AttrDict):
    """Flow.size"""

    def __init__(self, size):
        super().__init__(choice="fixed", fixed=size)


class IncrementSize(AttrDict):
    """Flow.size"""

    def __init__(self, start=1, end=1518, step=1):
        super().__init__(
            choice="increment",
            increment=dict(start=start, end=end, step=step),
        )


class RandomSize(AttrDict):
    """Flow.size"""

    def __init__(self, min=64, max=1518):
        super().__init__(choice="random", random=dict(min=min, max=max))


class Pps(AttrDict):
    """Flow.rate"""

    def __init__(self, pps=1000):
        super().__init__(choice="pps", pps=pps)


class Bps(AttrDict):
    """Flow.rate"""

    def __init__(self, bps=1000000000):
        super().__init__(choice="bps", bps=bps)


class Kbps(AttrDict):
    """Flow.rate"""

    def __init__(self, kbps=1000000):
        super().__init__(choice="kbps", kbps=kbps)


class Mbps(AttrDict):
    """Flow.rate"""

    def __init__(self, mbps=1000):
        super().__init__(choice="mbps", mbps=mbps)


class Gbps(AttrDict):
    """Flow.rate"""

    def __init__(self, gbps=1):
        super().__init__(choice="gbps", mbps=gbps)


class Percentage(AttrDict):
    """Flow.rate"""

    def __init__(self, percentage=100):
        super().__init__(choice="percentage", percentage=percentage)


class BytesDelay(AttrDict):
    """Flow.duration.delay"""

    def __init__(self, bytes=0):
        super().__init__(choice="bytes", bytes=bytes)


class NanosecondsDelay(AttrDict):
    """Flow.duration.delay"""

    def __init__(self, nanoseconds=0):
        super().__init__(choice="nanoseconds", nanoseconds=nanoseconds)


class MicrosecondsDelay(AttrDict):
    """Flow.duration.delay"""

    def __init__(self, microseconds=0):
        super().__init__(choice="microseconds", microseconds=microseconds)


class FixedPackets(AttrDict):
    """Flow.duration"""

    def __init__(self, packets=1, gap=12, delay=None):
        super().__init__(
            choice="fixed_packets",
            fixed_packets=dict(packets=packets, gap=gap),
        )
        if delay:
            self["fixed_packets"].update(delay=delay)


class FixedSeconds(AttrDict):
    """Flow.duration"""

    def __init__(self, seconds=1, gap=12, delay=None):
        super().__init__(
            choice="fixed_seconds",
            fixed_seconds=dict(seconds=seconds, gap=gap),
        )
        if delay:
            self["fixed_seconds"].update(delay=delay)


class Burst(AttrDict):
    """Flow.duration"""

    def __init__(self, packets, bursts=1, gap=12, inter_burst_gap=None):
        super().__init__(
            choice="burst",
            burst=dict(packets=packets, bursts=bursts, gap=gap),
        )
        if inter_burst_gap:
            self["burst"].update(inter_burst_gap=inter_burst_gap)


class Continuous(AttrDict):
    """Flow.duration"""

    def __init__(self, gap=12, delay=None):
        super().__init__(
            choice="continuous",
            continuous=dict(gap=gap),
        )
        if delay:
            self["continuous"].update(delay=delay)


class Metrics(AttrDict):
    """Flow.metrics"""

    def __init__(
        self,
        enable=False,
        loss=False,
        timestamps=False,
        latency_enable=False,
        latency_mode="store_forward",
    ):
        super().__init__(
            enable=enable,
            loss=loss,
            timestamps=timestamps,
            latency=dict(enable=latency_enable, mode=latency_mode),
        )
