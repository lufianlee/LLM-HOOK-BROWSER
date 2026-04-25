from __future__ import annotations

import asyncio
import logging
from threading import Thread

from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from app.config import settings
from app.proxy.interceptor import SecurityInterceptor, configure_interceptor

logger = logging.getLogger("proxy.runner")


class ProxyRunner:
    def __init__(self, event_queue: asyncio.Queue) -> None:
        self.event_queue = event_queue
        self._thread: Thread | None = None
        self._master: DumpMaster | None = None

    def start(self) -> None:
        configure_interceptor(
            api_base=f"http://{settings.api_host}:{settings.api_port}",
            target_domains=settings.target_domains,
            event_queue=self.event_queue,
        )
        self._thread = Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        opts = Options(listen_port=settings.proxy_port, ssl_insecure=True)
        self._master = DumpMaster(opts, loop=loop, with_termlog=False)
        self._master.addons.add(SecurityInterceptor())

        logger.info("Proxy listening on port %d", settings.proxy_port)
        try:
            loop.run_until_complete(self._master.run())
        except (KeyboardInterrupt, SystemExit):
            pass
        finally:
            if hasattr(self._master, "shutdown"):
                self._master.shutdown()

    def stop(self) -> None:
        if self._master and hasattr(self._master, "shutdown"):
            self._master.shutdown()
