# -*- coding: utf-8 -*-
import ipaddress
import json

import snappi
from pyrsistent import freeze

from apis.utils import AttrDict
from apis.utils import wait_for


class TrafficGenerator(object):
    """
    A high level traffic generator instance.

    Args:
        setting: <type apis.traffic_generator.Setting>
        location_preemption: Preempt all the test port locations as defined by
            the Port.Port.properties.location. If the test ports defined by
            their location values are in use and this value is true, the test
            ports will be preempted.
    """

    def __init__(self, setting, location_preemption=False):
        self.__api = snappi.api(location=setting.api_server, ext=setting.ext)
        self.setting = setting
        self.__location_preemption = location_preemption
        self.__config_cache = None
        self.__flows_config = None
        self.__captures_config = None
        self.__devices_config = None
        self.__lags_config = None

        self.apply_config()

    def __repr__(self):
        return str(self.setting)

    def apply_config(self):
        cfg = self.__api.config()

        if self.__config_cache is None or self.setting.ext != "ixnetwork":
            # ixnetwork just need to configure l1 settings at first time
            cfg.deserialize(self.setting.l1_config)
            cfg.options.port_options.location_preemption = (
                self.__location_preemption
            )

        cfg.deserialize(self.setting.ports_config)

        if self.__devices_config:
            cfg.devices.deserialize(self.__devices_config)

        if self.__lags_config:
            cfg.lags.deserialize(self.__lags_config)

        if self.__flows_config:
            cfg.flows.deserialize(self.__flows_config)

        if self.__captures_config:
            cfg.captures.deserialize(self.__captures_config)

        self.__api.set_config(cfg)
        self.__config_cache = cfg

    @property
    def config(self):
        return freeze(self.__config_cache)

    def set_flows(self, flows_config):
        self.__flows_config = flows_config

    def clear_flows(self):
        self.__flows_config = None
        self.stop_traffic()
        self.apply_config()

    def set_captures(self, captures_config):
        self.__captures_config = captures_config

    def clear_captures(self):
        self.__captures_config = None
        self.stop_capture()
        self.apply_config()

    def set_devices(self, devices_config):
        self.__devices_config = json.dumps(devices_config)

    def clear_devices(self):
        # it also needs to clear flows config or it will raise `Endpoints are
        # not properly configured in IxNetwork` error within apply confing.
        self.__devices_config = None
        self.__flows_config = None
        self.stop_all()
        self.apply_config()

    def set_lags(self, lags_config):
        self.__lags_config = json.dumps(lags_config)

    def clear_lags(self):
        # it also needs to clear flows config or it will raise `Endpoints are
        # not properly configured in IxNetwork` error within apply confing.
        self.__lags_config = None
        self.__flows_config = None
        self.stop_all()
        self.apply_config()

    def clear_all(self):
        self.__flows_config = None
        self.__captures_config = None
        self.__devices_config = None
        self.__lags_config = None
        self.stop_all()
        self.apply_config()

    def get_port_stats(self):
        """
        A example of return:

        {
            "port1": {
                [
                    {
                        "name": "port1",
                        "location": "10.168.4.60;2;25",
                        "link": "up",
                        "capture": "started",
                        "frames_tx": 0,
                        "frames_rx": 0,
                        "bytes_tx": 0,
                        "bytes_rx": 0,
                        "frames_tx_rate": 0,
                        "frames_rx_rate": 0,
                        "bytes_tx_rate": 0,
                        "bytes_rx_rate": 0,
                    }
                ]
            }
        }
        """
        metrics = AttrDict()

        req = self.__api.metrics_request()
        req.port.port_names = list()
        for item in self.__api.get_metrics(req).port_metrics:
            metrics[item.name] = item

        return metrics

    def get_flow_stats(self):
        """
        A example of return:

        {
            "Tx -> Rx": {
                [
                    {
                        "name": "Tx -> Rx",
                        "port_tx": "port1",
                        "port_rx": "port2",
                        "metric_groups": [],
                        "transmit": "started",
                        "frames_tx": 0,
                        "frames_rx": 0,
                        "bytes_tx": 0,
                        "bytes_rx": 0,
                        "frames_tx_rate": 0,
                        "frames_rx_rate": 0,
                        "loss": 0,
                        "timestamps": {},
                        "latency": {},
                    }
                ]
            }
        }
        """
        metrics = AttrDict()

        req = self.__api.metrics_request()
        req.flow.flow_names = list()

        for item in self.__api.get_metrics(req).flow_metrics:
            metrics[item.name] = item

        return metrics

    def get_bgpv4_stats(self):
        """
        A example of return:

        {
            "dev1": {
                [
                    {
                        "name": "dev1",
                        "session_state": "up",
                        "session_flap_count": 0,
                        "routes_advertised": 0,
                        "routes_received": 0,
                        "route_withdraws_sent": 0,
                        "route_withdraws_received": 0,
                        "updates_sent": 0,
                        "updates_received": 0,
                        "opens_sent": 0,
                        "opens_received": 0,
                        "keepalives_sent": 0,
                        "keepalives_received": 0,
                        "notifications_sent": 0,
                        "notifications_received": 0,
                    }
                ]
            }
        }
        """
        metrics = AttrDict()

        req = self.__api.metrics_request()
        req.bgpv4.peer_names = list()
        for item in self.__api.get_metrics(req).bgpv4_metrics:
            metrics[item.name] = item

        return metrics

    def get_bgpv6_stats(self):
        """
        A example of return:

        {
            "dev1": {
                [
                    {
                        "name": "dev1",
                        "session_state": "up",
                        "session_flap_count": 0,
                        "routes_advertised": 0,
                        "routes_received": 0,
                        "route_withdraws_sent": 0,
                        "route_withdraws_received": 0,
                        "updates_sent": 0,
                        "updates_received": 0,
                        "opens_sent": 0,
                        "opens_received": 0,
                        "keepalives_sent": 0,
                        "keepalives_received": 0,
                        "notifications_sent": 0,
                        "notifications_received": 0,
                    }
                ]
            }
        }
        """
        metrics = AttrDict()

        req = self.__api.metrics_request()
        req.bgpv6.peer_names = list()
        for item in self.__api.get_metrics(req).bgpv6_metrics:
            metrics[item.name] = item

        return metrics

    def get_captures(self):
        """
        A example of return:

        {
          "port1": <type 'BytesIO'>,
          "port2": <type 'BytesIO'>,
        }
        """
        captures = AttrDict()

        port_names = set(
            sum([c.port_names for c in self.__config_cache.captures], list())
        )

        for p in port_names:
            req = self.__api.capture_request()
            req.port_name = p
            captures[p] = self.__api.get_capture(req)

        return captures

    def is_transmit_stopped(self):
        """
        Returns true if traffic in stop state
        """
        f_stats = self.get_flow_stats().values()
        p_stats = self.get_port_stats().values()

        tx_started = all(m.frames_tx > 0 for m in f_stats)
        flow_stopped = all([m.transmit == "stopped" for m in f_stats])
        tx_rate = sum([m.frames_tx_rate for m in p_stats]) + sum(
            m.frames_tx_rate for m in f_stats
        )

        return tx_started and flow_stopped and tx_rate == 0

    def is_transmit_started(self):
        """
        Returns true if traffic in start state
        """
        f_stats = self.get_flow_stats().values()

        flow_started = all([m.transmit == "started" for m in f_stats])
        tx_started = all(m.frames_tx > 0 for m in f_stats)

        return flow_started and tx_started

    def send_ping(self, device_name, dst_ip):
        """
        API to send an IPv4 or IPv6 ICMP Echo Request(s) to dst. For each
        endpoint 1 ping packet will be sent and API shall wait for ping
        response to either be successful or timeout.The API wait timeout for
        each request is 300ms.

        Args:
            device_name: Name of endpoint device.
            dst_ip: The address to ping.
        """
        mode = f"ipv{ipaddress.ip_address(dst_ip).version}"
        self.start_protocol()
        device = next(
            d for d in self.__config_cache.devices if d.name == device_name
        )

        req = self.__api.ping_request()

        # FIXME
        # see: https://github.com/open-traffic-generator/models/pull/154
        (ip,) = getattr(req.endpoints, mode)()
        ip.src_name = getattr(device.ethernet, mode).name
        ip.dst_ip = dst_ip

        res = self.__api.send_ping(req).responses[-1]

        return res

    def start_traffic(self, flows, captures=None):
        """
        A high level api to applies flows/captures configuration,
        and starts traffic.

        Args:
            flows: The flows that will be configured on the traffic generator.
            captures: The capture settings that will be configured on the
                traffic generator.
        """
        self.set_flows(flows if isinstance(flows, list) else [flows])
        if captures is not None:
            self.set_captures(
                captures if isinstance(captures, list) else [captures]
            )

        self.apply_config()
        self.start_capture()
        self.start_transmit()

    def start_transmit(self, *flows):
        if flows:
            self.set_flows(list(flows))
            self.apply_config()

        if not self.__config_cache.flows:
            return

        ts = self.__api.transmit_state()
        ts.state = ts.START
        self.__api.set_transmit_state(ts)

    def start_capture(self, *captures):
        if captures:
            self.set_captures(list(captures))
            self.apply_config()

        if not self.__config_cache.captures:
            return

        cs = self.__api.capture_state()
        cs.port_names = set(
            sum([c.port_names for c in self.__config_cache.captures], list())
        )
        cs.state = cs.START
        self.__api.set_capture_state(cs)

    def start_protocol(self):
        # FIXME
        # see: https://github.com/open-traffic-generator/models/pull/154
        self.apply_config()
        if self.setting.ext == "ixnetwork":
            self.__api._assistant.Ixnetwork.StartAllProtocols(Arg1="sync")
        else:
            ts = self.__api.transmit_state()
            ts.state = ts.START
            self.__api.set_transmit_state(ts)

    def stop_traffic(self):
        # DEPRECATE WARNING: The naming should be more explicit, use
        # `stop_transmit` instead. The next chunk of code will be deprecated
        # in the future.
        self.stop_transmit()

    def stop_transmit(self):
        ts = self.__api.transmit_state()
        ts.state = ts.STOP
        self.__api.set_transmit_state(ts)

    def stop_capture(self):
        cs = self.__api.capture_state()
        cs.state = cs.STOP
        self.__api.set_capture_state(cs)

    def stop_protocol(self):
        # FIXME
        # see: https://github.com/open-traffic-generator/models/pull/154
        if self.setting.ext == "ixnetwork":

            def __is_ixn_protocol_stopped():
                if "started" == self.__api._globals.Topology.refresh().Status:
                    self.__api._assistant.Ixnetwork.StopAllProtocols(
                        Arg1="sync"
                    )
                return (
                    "notStarted"
                    == self.__api._globals.Topology.refresh().Status
                )

            wait_for(__is_ixn_protocol_stopped, timeout=120)
        else:
            ts = self.__api.transmit_state()
            ts.state = ts.STOP
            self.__api.set_transmit_state(ts)

    def stop_all(self):
        self.stop_transmit()
        self.stop_capture()
        self.stop_protocol()

    def link_up_ports(self, *port_names):
        ls = self.__api.link_state()
        ls.port_names = port_names
        ls.state = "up"
        self.__api.set_link_state(ls)

    def link_down_ports(self, *port_names):
        ls = self.__api.link_state()
        ls.port_names = port_names
        ls.state = "down"
        self.__api.set_link_state(ls)

    def teardown(self):
        self.stop_all()

        # clear all settings (includes l1 settings)
        self.__api.set_config(self.__api.config())
        if getattr(self.__api, "assistant", None):
            self.__api.assistant.Session.remove()
