"""Tests for the FireServiceRotaIncidents websocket listener."""

import json
import queue
import threading
from collections import deque

import pytest
import websocket

from pyfireservicerota import FireServiceRotaIncidents

from .conftest import (
    CONFIRM,
    PING,
    SUBSCRIBE,
    URL,
    WAIT,
    WELCOME,
    FakeWebSocket,
    incident,
)


@pytest.fixture
def listener():
    received = queue.Queue()
    client = FireServiceRotaIncidents(on_incident=received.put)
    client.received = received
    yield client
    client.stop()
    if client.wst is not None:
        client.wst.join(WAIT)
        assert not client.wst.is_alive()


def listen(client, ws):
    """Run the receive loop inline on an already scripted socket."""
    return client._listen(ws, threading.Event(), deque(maxlen=30))


# --- message handling -----------------------------------------------------


def test_welcome_subscribes_to_incident_channel():
    ws = FakeWebSocket([WELCOME, (websocket.ABNF.OPCODE_CLOSE, "")])

    assert listen(FireServiceRotaIncidents(), ws) is True
    assert ws.sent == [SUBSCRIBE]


def test_connection_closed_before_welcome_is_not_welcomed():
    ws = FakeWebSocket([(websocket.ABNF.OPCODE_CLOSE, "")])

    assert listen(FireServiceRotaIncidents(), ws) is False
    assert ws.sent == []


def test_incident_is_marked_new_then_update():
    received = []
    ws = FakeWebSocket(
        [
            WELCOME,
            CONFIRM,
            incident(1, body="fire"),
            incident(2),
            incident(1, body="fire, updated"),
            (websocket.ABNF.OPCODE_CLOSE, ""),
        ]
    )

    listen(FireServiceRotaIncidents(on_incident=received.append), ws)

    assert received == [
        {"id": 1, "body": "fire", "trigger": "new"},
        {"id": 2, "trigger": "new"},
        {"id": 1, "body": "fire, updated", "trigger": "update"},
    ]


def test_only_the_last_30_incidents_are_remembered():
    received = []
    script = [incident(i) for i in range(31)] + [incident(0)]
    ws = FakeWebSocket([*script, (websocket.ABNF.OPCODE_CLOSE, "")])

    listen(FireServiceRotaIncidents(on_incident=received.append), ws)

    # Incident 0 was pushed out of the cache by 30 newer ones
    assert received[-1] == {"id": 0, "trigger": "new"}


@pytest.mark.parametrize(
    "message",
    [
        "not json",
        PING,
        json.dumps({"message": {"id": 1}}),
        json.dumps(
            {
                "identifier": json.dumps({"channel": "OtherChannel"}),
                "message": {"id": 1},
            }
        ),
        json.dumps(
            {
                "identifier": json.dumps(
                    {"channel": "IncidentNotificationsChannel"}
                ),
                "message": {"no_id": True},
            }
        ),
    ],
)
def test_other_messages_are_ignored(message):
    received = []
    ws = FakeWebSocket(
        [message, incident(5), (websocket.ABNF.OPCODE_CLOSE, "")]
    )

    listen(FireServiceRotaIncidents(on_incident=received.append), ws)

    # The bad message is skipped and the listener keeps going
    assert received == [{"id": 5, "trigger": "new"}]


def test_failing_callback_does_not_stop_the_listener():
    received = []

    def on_incident(data):
        received.append(data["id"])
        if data["id"] == 1:
            raise RuntimeError("boom")

    ws = FakeWebSocket(
        [incident(1), incident(2), (websocket.ABNF.OPCODE_CLOSE, "")]
    )

    listen(FireServiceRotaIncidents(on_incident=on_incident), ws)

    assert received == [1, 2]


def test_incidents_without_callback_are_accepted():
    ws = FakeWebSocket([incident(1), (websocket.ABNF.OPCODE_CLOSE, "")])

    assert listen(FireServiceRotaIncidents(), ws) is False


# --- keepalive ------------------------------------------------------------


def test_silence_triggers_ping_and_reply_restores_interval():
    ws = FakeWebSocket(
        [
            websocket.WebSocketTimeoutException(),
            (websocket.ABNF.OPCODE_PONG, ""),
            (websocket.ABNF.OPCODE_CLOSE, ""),
        ]
    )
    client = FireServiceRotaIncidents(ping_interval=6, ping_timeout=4)

    listen(client, ws)

    assert ws.pings == 1
    # interval while idle, timeout while awaiting the pong, interval again
    assert ws.timeouts == [6, 4, 6]


def test_unanswered_ping_ends_the_connection():
    ws = FakeWebSocket(
        [
            WELCOME,
            websocket.WebSocketTimeoutException(),
            websocket.WebSocketTimeoutException(),
            incident(1),
        ]
    )
    received = []

    welcomed = listen(
        FireServiceRotaIncidents(on_incident=received.append), ws
    )

    assert welcomed is True
    assert ws.pings == 1
    assert received == []


def test_failing_ping_ends_the_connection():
    ws = FakeWebSocket([websocket.WebSocketTimeoutException()])
    ws.ping = lambda: (_ for _ in ()).throw(OSError("broken pipe"))

    assert listen(FireServiceRotaIncidents(), ws) is False


@pytest.mark.parametrize(
    "error",
    [
        websocket.WebSocketConnectionClosedException("gone"),
        OSError("reset"),
    ],
)
def test_receive_error_ends_the_connection(error):
    ws = FakeWebSocket([WELCOME, error])

    assert listen(FireServiceRotaIncidents(), ws) is True


def test_zero_ping_interval_disables_the_timeout():
    ws = FakeWebSocket([(websocket.ABNF.OPCODE_CLOSE, "")])

    listen(FireServiceRotaIncidents(ping_interval=0), ws)

    assert ws.timeouts == [None]


# --- lifecycle ------------------------------------------------------------


def test_start_connects_and_delivers_incidents(server, listener):
    ws = server.expect(FakeWebSocket([WELCOME, incident(1)]))

    listener.start(URL)

    assert server.wait_for_attempt() == (URL, listener.connect_timeout)
    assert listener.received.get(timeout=WAIT) == {"id": 1, "trigger": "new"}
    assert listener.is_running is True
    assert ws.sent == [SUBSCRIBE]


def test_stop_aborts_the_socket_and_ends_the_thread(server, listener):
    ws = server.expect(FakeWebSocket([WELCOME, incident(1)]))
    listener.start(URL)
    listener.received.get(timeout=WAIT)

    listener.stop()
    listener.wst.join(WAIT)

    assert listener.is_running is False
    assert not listener.wst.is_alive()
    assert ws.aborted.is_set()
    assert ws.shutdown_called.is_set()
    assert listener.ws is None
    # No reconnect after a stop
    assert server.attempts.qsize() == 1


def test_stop_before_start_is_harmless():
    FireServiceRotaIncidents().stop()


def test_reconnects_after_dropped_connection(server, listener):
    first = server.expect(
        FakeWebSocket(
            [
                WELCOME,
                incident(1),
                websocket.WebSocketConnectionClosedException("dropped"),
            ]
        )
    )
    server.expect(FakeWebSocket([WELCOME, incident(2)]))

    listener.start(URL)

    assert listener.received.get(timeout=WAIT)["id"] == 1
    assert listener.received.get(timeout=WAIT)["id"] == 2
    assert first.shutdown_called.is_set()


def test_incident_seen_before_reconnect_is_an_update_after(server, listener):
    server.expect(
        FakeWebSocket(
            [WELCOME, incident(1), (websocket.ABNF.OPCODE_CLOSE, "")]
        )
    )
    server.expect(FakeWebSocket([WELCOME, incident(1)]))

    listener.start(URL)

    assert listener.received.get(timeout=WAIT)["trigger"] == "new"
    assert listener.received.get(timeout=WAIT)["trigger"] == "update"


def test_keeps_retrying_when_connecting_fails(server, listener):
    server.expect(OSError("refused"))
    server.expect(websocket.WebSocketBadStatusException("bad %s %s", 401))
    server.expect(ValueError("unexpected"))
    server.expect(FakeWebSocket([WELCOME, incident(1)]))

    listener.start(URL)

    assert listener.received.get(timeout=WAIT)["id"] == 1
    assert server.attempts.qsize() == 4


def test_on_connect_failed_called_when_not_welcomed(server):
    failures = queue.Queue()
    client = FireServiceRotaIncidents(
        on_connect_failed=lambda: failures.put(1)
    )
    server.expect(OSError("refused"))
    server.expect(FakeWebSocket([(websocket.ABNF.OPCODE_CLOSE, "")]))

    try:
        client.start(URL)
        failures.get(timeout=WAIT)
        failures.get(timeout=WAIT)
    finally:
        client.stop()
        client.wst.join(WAIT)


def test_on_connect_failed_not_called_after_welcome(server):
    failures = queue.Queue()
    received = queue.Queue()
    client = FireServiceRotaIncidents(
        on_incident=received.put,
        on_connect_failed=lambda: failures.put(1),
    )
    server.expect(FakeWebSocket([WELCOME, (websocket.ABNF.OPCODE_CLOSE, "")]))
    server.expect(FakeWebSocket([WELCOME, incident(1)]))

    try:
        client.start(URL)
        received.get(timeout=WAIT)
    finally:
        client.stop()
        client.wst.join(WAIT)

    assert failures.empty()


def test_failing_on_connect_failed_does_not_stop_retrying(server):
    received = queue.Queue()

    def on_connect_failed():
        raise RuntimeError("boom")

    client = FireServiceRotaIncidents(
        on_incident=received.put, on_connect_failed=on_connect_failed
    )
    server.expect(OSError("refused"))
    server.expect(FakeWebSocket([WELCOME, incident(1)]))

    try:
        client.start(URL)
        assert received.get(timeout=WAIT)["id"] == 1
    finally:
        client.stop()
        client.wst.join(WAIT)


def test_restart_from_on_connect_failed_uses_the_new_url(server):
    new_url = URL.replace("access-1", "access-2")
    received = queue.Queue()
    client = FireServiceRotaIncidents(on_incident=received.put)
    client.on_connect_failed = lambda: client.start(new_url)
    server.expect(websocket.WebSocketBadStatusException("bad %s %s", 401))
    server.expect(FakeWebSocket([WELCOME, incident(1)]))

    try:
        client.start(URL)
        assert received.get(timeout=WAIT)["id"] == 1
        assert server.wait_for_attempt()[0] == URL
        assert server.wait_for_attempt()[0] == new_url
        assert client.is_running is True
    finally:
        client.stop()
        client.wst.join(WAIT)


def test_stop_from_on_connect_failed_ends_the_listener(server):
    client = FireServiceRotaIncidents()
    client.on_connect_failed = client.stop
    server.expect(OSError("refused"))

    client.start(URL)
    client.wst.join(WAIT)

    assert not client.wst.is_alive()
    assert client.is_running is False
    assert server.attempts.qsize() == 1


def test_start_while_running_replaces_the_listener(server, listener):
    first = server.expect(FakeWebSocket([WELCOME, incident(1)]))
    listener.start(URL)
    listener.received.get(timeout=WAIT)
    first_thread = listener.wst

    server.expect(FakeWebSocket([WELCOME, incident(1)]))
    listener.start(URL)

    # A fresh run forgets earlier incidents, so this is "new" again
    assert listener.received.get(timeout=WAIT)["trigger"] == "new"
    first_thread.join(WAIT)
    assert not first_thread.is_alive()
    assert first.aborted.is_set()
    assert listener.wst is not first_thread
