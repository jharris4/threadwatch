"""Keep the suite off the LAN.

A recorder that is not replaying browses for border routers over mDNS on
its first periodic tick, on a thread of its own. Most tests build such a
recorder without meaning to test that, and the suite used to send real
multicast queries every run and leak browse threads past their tests:
one still waiting when test_mdns swapped select() for a fake died there
with a traceback nobody had asked for.

This used to be opt-in, imported by each module that knew it needed it,
which protected only the modules that remembered and left the hole open
for the next one (test_doctor reached a real browse through a check).
tests/__init__.py now calls install() before any test module is
imported, so the guard costs nothing to get right: the browse answers at
once with an empty LAN, the thread logic still runs, and nothing leaves
the box. A test of the browse itself asks for the real one back with
real_browse() (test_mdns does), or installs its own fake over this one
(test_pipeline does).
"""

import contextlib
from typing import Iterator

from threadwatch import mdns

_real_browse = mdns.browse


def no_browse(timeout: float = 4.0, **_kw) -> list:
    return []


def install() -> None:
    """Point mdns.browse at the empty LAN, for the whole run."""
    mdns.browse = no_browse


@contextlib.contextmanager
def real_browse() -> Iterator[None]:
    """The real browse, for a test of the browse itself. Whatever it opens
    must be faked at the socket layer (mdns.socket), not left to the LAN."""
    mdns.browse = _real_browse
    try:
        yield
    finally:
        mdns.browse = no_browse
