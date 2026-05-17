"""Per-participant ARES session.

:class:`ARESSession` owns one WebSocket connection plus the inbound
message queue. Methods are async and named for the smoke-test idiom:

    msg = await session.expect("auction.invitation")
    await session.send("auction.keygen.share", {"round": 1, "share": "..."})
    await session.close()

The receive pump runs in the background; messages arrive in an
``asyncio.Queue`` and :meth:`expect` / :meth:`receive_any` drain it.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse

import websockets
from websockets.asyncio.client import ClientConnection

from .config import ARESClientError

log = logging.getLogger(__name__)


@dataclass
class WSMessage:
    """One inbound WebSocket frame."""

    type: str
    session_id: str = ""
    seq: int = 0
    payload: Any = None
    timestamp: str = ""
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_json(cls, data: dict) -> "WSMessage":
        return cls(
            type=data.get("type", ""),
            session_id=data.get("session_id", ""),
            seq=data.get("seq", 0),
            payload=data.get("payload"),
            timestamp=data.get("timestamp", ""),
            raw=data,
        )


def _derive_ws_token(secret: str, pseudonym: str) -> str:
    """HMAC-SHA256(secret, pseudonym) hex — matches transport.AuthMiddleware."""
    mac = hmac.new(secret.encode("utf-8"), pseudonym.encode("utf-8"), hashlib.sha256)
    return mac.hexdigest()


def _ws_url(server_url: str, pseudonym: str, token: str) -> str:
    parsed = urlparse(server_url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    query = urlencode({"pseudonym": pseudonym, "auth": token})
    return urlunparse((scheme, parsed.netloc, "/v2/ws", "", query, ""))


class ARESSession:
    """One participant's view of a session.

    Construct via :meth:`connect`; the helper does the WS handshake and
    starts the receive pump.
    """

    def __init__(
        self,
        pseudonym: str,
        ws: ClientConnection,
        session_id: str,
        default_timeout: float = 30.0,
    ) -> None:
        self.pseudonym = pseudonym
        self.session_id = session_id
        self._ws = ws
        self._inbox: asyncio.Queue[WSMessage] = asyncio.Queue()
        self._default_timeout = default_timeout
        self._closed = False
        self._recv_task = asyncio.create_task(self._recv_loop(), name=f"recv-{pseudonym}")

    # Construction ---------------------------------------------------

    @classmethod
    async def connect(
        cls,
        server_url: str,
        pseudonym: str,
        session_id: str,
        auth_secret: str = "",
        default_timeout: float = 30.0,
    ) -> "ARESSession":
        """Open a WS connection, authenticated for ``pseudonym``."""
        token = _derive_ws_token(auth_secret, pseudonym) if auth_secret else ""
        url = _ws_url(server_url, pseudonym, token)
        log.debug("[%s] dialing %s", pseudonym, url)
        try:
            ws = await websockets.connect(
                url,
                ping_interval=20,
                ping_timeout=30,
                close_timeout=5,
                max_size=64 * 1024 * 1024,  # 64 MiB — large CKKS payloads
            )
        except Exception as e:
            raise ARESClientError(f"dial WS for {pseudonym!r}: {e}") from e
        return cls(pseudonym, ws, session_id, default_timeout=default_timeout)

    # Sending --------------------------------------------------------

    async def send(self, msg_type: str, payload: Any = None, seq: int = 0) -> None:
        """Send a WS frame. ``payload`` is JSON-serialized if non-None."""
        if self._closed:
            raise ARESClientError(f"{self.pseudonym}: session closed")
        frame = {
            "type": msg_type,
            "session_id": self.session_id,
            "seq": seq,
        }
        if payload is not None:
            frame["payload"] = payload
        body = json.dumps(frame)
        log.debug("[%s] → %s (%d bytes)", self.pseudonym, msg_type, len(body))
        await self._ws.send(body)

    # Receiving ------------------------------------------------------

    async def expect(self, msg_type: str, timeout: float | None = None) -> WSMessage:
        """Wait for the next frame of ``msg_type``. Other frames are dropped.

        Raises :class:`ARESClientError` if the timeout elapses.
        """
        deadline = time.monotonic() + (timeout if timeout is not None else self._default_timeout)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ARESClientError(
                    f"{self.pseudonym}: timeout waiting for {msg_type!r}"
                )
            try:
                msg = await asyncio.wait_for(self._inbox.get(), timeout=remaining)
            except asyncio.TimeoutError:
                raise ARESClientError(
                    f"{self.pseudonym}: timeout waiting for {msg_type!r}"
                ) from None
            if msg.type == msg_type:
                return msg
            log.debug("[%s] dropped %s (waiting for %s)", self.pseudonym, msg.type, msg_type)

    async def receive_any(self, timeout: float | None = None) -> WSMessage:
        """Return the next frame regardless of type."""
        t = timeout if timeout is not None else self._default_timeout
        try:
            return await asyncio.wait_for(self._inbox.get(), timeout=t)
        except asyncio.TimeoutError:
            raise ARESClientError(
                f"{self.pseudonym}: timeout waiting for any frame"
            ) from None

    # Lifecycle ------------------------------------------------------

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._recv_task.cancel()
        try:
            await self._ws.close()
        except Exception:  # noqa: BLE001 — close on a flaky socket is best-effort
            pass

    async def __aenter__(self) -> "ARESSession":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    # Internals ------------------------------------------------------

    async def _recv_loop(self) -> None:
        try:
            async for raw in self._ws:
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    log.warning("[%s] non-JSON frame, dropped", self.pseudonym)
                    continue
                msg = WSMessage.from_json(data)
                await self._inbox.put(msg)
                log.debug("[%s] ← %s", self.pseudonym, msg.type)
        except asyncio.CancelledError:
            pass
        except websockets.exceptions.ConnectionClosed as e:
            log.debug("[%s] WS closed: %s", self.pseudonym, e)
        except Exception as e:  # noqa: BLE001
            log.warning("[%s] recv loop error: %s", self.pseudonym, e)
