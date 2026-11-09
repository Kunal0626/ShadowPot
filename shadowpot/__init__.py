"""ShadowPot: SSH honeypot log analytics.

Modules:
    parser  one raw Cowrie JSON line -> a typed, canonicalized Event. Pure:
            no database, no filesystem, no clock.
    db      connections, the SQLite/MySQL dialect switch, schema application.
    ingest  the loader: idempotent, resumable, rotation-aware.
"""

__version__ = "0.4.0"
