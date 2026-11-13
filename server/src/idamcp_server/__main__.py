"""Entry point: `idamcp-server` (stdio transport, launched by Claude Code)."""

from __future__ import annotations

import json
import logging
import os
import sys


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)
        return json.dumps(out)


def main() -> None:
    level = os.environ.get("IDAMCP_LOG_LEVEL", "INFO").upper()
    handler = logging.StreamHandler(sys.stderr)  # stdout is the MCP wire
    handler.setFormatter(_JsonFormatter())
    logging.basicConfig(level=level if level in {"DEBUG", "INFO", "WARNING", "ERROR"} else "INFO",
                        handlers=[handler], force=True)

    try:
        timeout_ms = int(os.environ.get("IDAMCP_TIMEOUT_MS", "15000"))
    except ValueError:
        timeout_ms = 15000
    timeout_ms = max(1000, min(timeout_ms, 120000))

    from .server import default_server

    logging.getLogger("idamcp").info("starting idamcp-server (timeout %d ms)", timeout_ms)
    default_server(timeout_ms=timeout_ms).run()


if __name__ == "__main__":
    main()
