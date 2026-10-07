"""Make the server process non-dumpable on Linux (GH-188, security audit M-1).

Purpose:
    The document conversion child (``admino.converters.runner``) runs untrusted
    parsers (PDFium, Pillow, libxml2) as the same user as the server. Its
    environment is scrubbed, but a same-uid process can still read the
    server's original environment (``PG_APP_PASSWORD``, ``OAUTH_ENCRYPTION_KEY``,
    API tokens), its open file descriptors and, where ptrace is allowed, its
    memory through ``/proc/<server pid>/``. ``prctl(PR_SET_DUMPABLE, 0)`` makes
    those ``/proc`` entries root-owned, so a compromised parser gets
    ``PermissionError`` there; it also disables core dumps of the server. The
    child is unaffected: ``exec`` makes it dumpable again.

Inputs:
    None. Called once by ``admino.main`` before the server starts.

Outputs:
    ``make_non_dumpable()`` returns True when the kernel accepted the call,
    False off Linux or on any failure.

Security notes:
    - Never raises and never logs: startup goes on without the hardening, and
      ``admino.main`` logs the one warning (an errno or exception text never
      reaches a log).
    - The C library is loaded at call time through ``ctypes``; no argument
      comes from outside this module.
"""

from __future__ import annotations

import ctypes
import sys
from typing import Final

# From <linux/prctl.h>: the option, and the value that turns dumpability off.
_PR_SET_DUMPABLE: Final = 4
_SUID_DUMP_DISABLE: Final = 0


def make_non_dumpable() -> bool:
    """Turn the current process's dumpable flag off (Linux only).

    Calls ``prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)`` through the C library already
    loaded in the process (``ctypes.CDLL(None)``).

    Returns:
        True when prctl returned 0; False on any other platform, when the
        library or its ``prctl`` symbol can't be loaded, or when prctl fails.
    """
    if sys.platform != "linux":
        return False
    try:
        prctl = ctypes.CDLL(None, use_errno=True).prctl
    except (OSError, AttributeError):
        return False
    # prctl is variadic: arguments 2-5 are passed as unsigned long, so no
    # register carries undefined upper bits the kernel would reject.
    unused = ctypes.c_ulong(0)
    result: int = prctl(
        ctypes.c_int(_PR_SET_DUMPABLE), ctypes.c_ulong(_SUID_DUMP_DISABLE), unused, unused, unused
    )
    return result == 0
