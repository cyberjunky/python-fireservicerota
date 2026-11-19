"""Shared fixtures for the pyfireservicerota tests."""

import json
import queue
import threading

import pytest
import responses
import websocket

import pyfireservicerota
from pyfireservicerota import FireServiceRota

BASE_URL = "www.example.test"
API = f"https://{BASE_URL}/api/v2"
TOKEN_URL = f"https://{BASE_URL}/oauth/token"

TOKEN_INFO = {
    "access_token": "access-1",
    "refresh_token": "refresh-1",
    "token_type": "Bearer",
    "expires_in": 7200,
}

USER = {"id": 42, "memberships": [{"id": 7}]}


@pytest.fixture
def mocked():
    """Intercept every HTTP request made through `requests`."""
    with responses.RequestsMock() as rsps:
        yield rsps


@pytest.fixture
def api():
    """A client that already holds tokens."""
    return FireServiceRota(
        base_url=BASE_URL,
        username="user@example.test",
        password="secret",
        token_info=dict(TOKEN_INFO),
    )


# --- websocket fakes ------------------------------------------------------

URL = "wss://www.example.test/cable?access_token=access-1"
WAIT = 5  # generous upper bound; tests normally finish in milliseconds

WELCOME = json.dumps({"type": "welcome"})
PING = json.dumps({"type": "ping", "message": 1})
CONFIRM = json.dumps({"type": "confirm_subscription"})
SUBSCRIBE = {
    "command": "subscribe",
    "identifier": json.dumps({"channel": "IncidentNotificationsChannel"}),
}


def incident(incident_id, **extra):
    return json.dumps(
        {
            "identifier": json.dumps(
                {"channel": "IncidentNotificationsChannel"}
            ),
            "message": {"id": incident_id, **extra},
        }
    )


class Frame:
    def __init__(self, text):
        self.data = text.encode("utf-8")


class FakeWebSocket:
    """A scripted stand-in for websocket.WebSocket.

    Items in the script are text messages, ``(opcode, text)`` tuples or
    exceptions to raise. Once the script is exhausted, recv blocks until
    the socket is aborted, like a real idle connection.
    """

    def __init__(self, script=()):
        self._script = queue.Queue()
        for item in script:
            self._script.put(item)
        self.sent = []
        self.pings = 0
        self.timeouts = []
        self.aborted = threading.Event()
        self.shutdown_called = threading.Event()

    def feed(self, item):
        self._script.put(item)

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def recv_data_frame(self, control_frame=False):
        while True:
            if self.aborted.is_set():
                raise websocket.WebSocketConnectionClosedException("aborted")
            try:
                item = self._script.get(timeout=0.01)
            except queue.Empty:
                continue
            if isinstance(item, BaseException):
                raise item
            if isinstance(item, tuple):
                opcode, text = item
                return opcode, Frame(text)
            return websocket.ABNF.OPCODE_TEXT, Frame(item)

    def send(self, payload):
        self.sent.append(json.loads(payload))

    def ping(self):
        self.pings += 1

    def abort(self):
        self.aborted.set()

    def shutdown(self):
        self.shutdown_called.set()


class FakeServer:
    """Replaces websocket.create_connection and records every attempt."""

    def __init__(self, monkeypatch):
        self._outcomes = queue.Queue()
        self.attempts = queue.Queue()
        monkeypatch.setattr(
            pyfireservicerota.websocket, "create_connection", self._connect
        )

    def expect(self, outcome):
        """Queue a FakeWebSocket to hand out, or an exception to raise."""
        self._outcomes.put(outcome)
        return outcome

    def _connect(self, url, timeout=None):
        self.attempts.put((url, timeout))
        try:
            outcome = self._outcomes.get_nowait()
        except queue.Empty:
            # Nothing scripted: an idle connection that never welcomes us
            outcome = FakeWebSocket()
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def wait_for_attempt(self):
        return self.attempts.get(timeout=WAIT)


@pytest.fixture
def server(monkeypatch):
    # Reconnect without real waiting
    monkeypatch.setattr(pyfireservicerota, "RECONNECT_DELAY_MAX", 0.01)
    return FakeServer(monkeypatch)
