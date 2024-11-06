# -*- coding: utf-8 -*-
import json


class Setting(object):
    """
    Singleton for global settings
    """

    def __init__(self, **kwargs):
        self.api_server = kwargs["api_server"]
        self.ext = kwargs.get("ext", None)

        layer1 = kwargs["config"]
        ports = layer1.pop("ports")
        if "name" not in layer1.keys():
            layer1["name"] = "layer1"
        if "port_names" not in layer1.keys():
            layer1["port_names"] = [port["name"] for port in ports]

        self.l1_config = json.dumps(dict(layer1=[layer1]))
        self.ports_config = json.dumps(dict(ports=ports))

    def __str__(self):
        return json.dumps(
            dict(ports=self.ports_config, layer1=[self.l1_config])
        )

    def __repr__(self):
        return str(self)
