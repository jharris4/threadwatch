"""Keep the suite off the LAN.

A recorder that is not replaying browses for border routers over mDNS on
its first periodic tick, on a thread of its own. Most tests build such a
recorder without meaning to test that, and the suite used to send real
multicast queries every run and leak browse threads past their tests:
one still waiting when test_mdns swapped select() for a fake died there
with a traceback nobody had asked for. Import this module's
setUpModule / tearDownModule into any test module that builds a
non-replay Pipeline: the browse answers at once with an empty LAN, so
the thread logic still runs and nothing leaves the box. A test of the
browse itself installs its own fake over this one (test_pipeline does)
or patches mdns.socket (test_mdns, which must not import this).
"""

from unittest import mock

from threadwatch import mdns

_patchers: list = []


def no_browse(timeout: float = 4.0, **_kw) -> list:
    return []


def setUpModule() -> None:
    p = mock.patch.object(mdns, "browse", no_browse)
    p.start()
    _patchers.append(p)


def tearDownModule() -> None:
    _patchers.pop().stop()
