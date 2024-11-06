# -*- coding: utf-8 -*-
import re

from apis.utils import AttrDict


_CAPTURE_NAME_RE = re.compile(r"^[\w]+$")


class Capture(AttrDict):
    """
    Configuration for capture settings.
    see: https://github.com/open-traffic-generator/models/tree/master/capture

    Typical usage example:

    capture = Capture(
        port_names=["port1"],
        filters=[
            AttrFilter(value="0000faceface", mask="00000000000b", negate=True)
        ],
    )
    """

    def __init__(
        self,
        name,
        port_names,
        filters=None,
        overwrite=True,
        packet_size=0,
        format="pcap",
    ):
        super().__init__(
            name=name,
            port_names=port_names,
            overwrite=overwrite,
            packet_size=packet_size,
            format=format,
        )

        if filters:
            self.update(filters=filters)

    def __setitem__(self, key, value):
        if key == "name" and not _CAPTURE_NAME_RE.match(value):
            raise NameError(
                f"capture name '{value}' is not valid, "
                "only accepts `[a-zA-Z0-9_]` characters"
            )

        super().__setitem__(key, value)

    def update(self, *args, **kwargs):
        for k, v in dict(*args, **kwargs).items():
            self[k] = v


class AttrFilter(AttrDict):
    """Capture.filters"""

    def __init__(self, value, mask, negate=False):
        super().__init__(value=value, mask=mask, negate=negate)
