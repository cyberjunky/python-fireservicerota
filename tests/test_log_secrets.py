"""Nothing that is logged may contain a password or a token."""

import logging
import queue

import pytest
import requests
import websocket

from pyfireservicerota import (
    ExpiredTokenError,
    FireServiceRota,
    FireServiceRotaIncidents,
    InvalidAuthError,
)

from .conftest import (
    API,
    BASE_URL,
    TOKEN_URL,
    USER,
    WAIT,
    WELCOME,
    FakeWebSocket,
    incident,
)

PASSWORD = "s3cret-p@ssword"
ACCESS = "access-token-aaaa"
REFRESH = "refresh-token-bbbb"
NEW_ACCESS = "access-token-cccc"
NEW_REFRESH = "refresh-token-dddd"
SECRETS = [
    PASSWORD,
    "s3cret-p%40ssword",  # the password as it is URL-encoded
    ACCESS,
    REFRESH,
    NEW_ACCESS,
    NEW_REFRESH,
]


@pytest.fixture
def logs(caplog):
    """Capture every logger at DEBUG and check the output afterwards."""
    caplog.set_level(logging.DEBUG)
    yield caplog
    records = caplog.get_records("call")
    assert records, "expected the scenario to log something"
    for record in records:
        # exc_text holds a formatted traceback, if any
        text = f"{record.getMessage()}\n{record.exc_text or ''}"
        for secret in SECRETS:
            assert secret not in text


def _client(**kwargs):
    return FireServiceRota(BASE_URL, "user@example.test", PASSWORD, **kwargs)


def _tokens(access=ACCESS, refresh=REFRESH):
    return {"access_token": access, "refresh_token": refresh}


def test_request_tokens(mocked, logs):
    mocked.post(TOKEN_URL, json=_tokens())

    _client().request_tokens()


def test_refresh_tokens(mocked, logs):
    mocked.post(TOKEN_URL, json=_tokens(NEW_ACCESS, NEW_REFRESH))

    _client(token_info=_tokens()).refresh_tokens()


def test_api_calls(mocked, logs):
    mocked.get(f"{API}/users/current.json", json=USER)
    mocked.post(f"{API}/pagers/3/messages", json={"id": 11})
    api = _client(token_info=_tokens())

    api.get_user()
    api.send_pager_message(3, "hi", address="123")


def test_rejected_credentials(mocked, logs):
    mocked.post(TOKEN_URL, json={"error": "invalid_grant"}, status=401)

    with pytest.raises(InvalidAuthError):
        _client().request_tokens()


def test_expired_token(mocked, logs):
    mocked.get(f"{API}/skills", json={"error": "token_expired"}, status=401)

    with pytest.raises(ExpiredTokenError):
        _client(token_info=_tokens()).get_skills()


@pytest.mark.parametrize("status", [400, 500])
def test_token_endpoint_error_echoing_the_request(mocked, logs, status):
    # A server or proxy that echoes what we sent must not leak through us
    mocked.post(
        TOKEN_URL,
        json={"error": "server_error", "echo": PASSWORD, "token": REFRESH},
        status=status,
    )

    _client().request_tokens()
    _client(token_info=_tokens()).refresh_tokens()


@pytest.mark.parametrize(
    "error", [requests.exceptions.Timeout, requests.exceptions.ConnectionError]
)
def test_network_errors(mocked, logs, error):
    # requests quotes the request URL in these errors, as the real ones do
    def fail(request):
        raise error(f"Max retries exceeded with url: {request.url}")

    mocked.add_callback("POST", TOKEN_URL, callback=fail)
    mocked.add_callback("GET", f"{API}/skills", callback=fail)
    api = _client(token_info=_tokens())

    api.request_tokens()
    api.refresh_tokens()
    api.get_skills()


def test_invalid_json_from_token_endpoint(mocked, logs):
    mocked.post(TOKEN_URL, body="<html>oops</html>")

    _client().request_tokens()


def test_websocket_listener(server, logs):
    url = f"wss://{BASE_URL}/cable?access_token={ACCESS}"
    received = queue.Queue()
    client = FireServiceRotaIncidents(on_incident=received.put)
    # Errors that quote the URL, as websocket-client and the OS can do
    server.expect(OSError(f"cannot connect to {url}"))
    server.expect(websocket.WebSocketException(f"bad handshake for {url}"))
    server.expect(ValueError(f"unexpected for token {ACCESS}"))
    server.expect(
        FakeWebSocket([WELCOME, incident(1), OSError(f"lost {url}")])
    )
    server.expect(FakeWebSocket([WELCOME, incident(2)]))

    try:
        client.start(url)
        assert received.get(timeout=WAIT)["id"] == 1
        assert received.get(timeout=WAIT)["id"] == 2
    finally:
        client.stop()
        client.wst.join(WAIT)
