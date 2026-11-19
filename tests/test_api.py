"""Tests for the FireServiceRota REST client."""

import datetime
import json
from urllib.parse import parse_qs, urlparse

import pytest
import requests

from pyfireservicerota import (
    ExpiredTokenError,
    FireServiceRota,
    InvalidAuthError,
    InvalidTokenError,
)

from .conftest import API, BASE_URL, TOKEN_INFO, TOKEN_URL, USER


def _query(request):
    return {k: v[0] for k, v in parse_qs(urlparse(request.url).query).items()}


def _form(request):
    assert (
        request.headers["Content-Type"] == "application/x-www-form-urlencoded"
    )
    return {k: v[0] for k, v in parse_qs(request.body).items()}


# --- tokens ---------------------------------------------------------------


def test_request_tokens_stores_and_returns_tokens(mocked):
    mocked.post(TOKEN_URL, json=TOKEN_INFO)
    api = FireServiceRota(BASE_URL, "user@example.test", "secret")

    assert api.request_tokens() == TOKEN_INFO

    request = mocked.calls[0].request
    assert _form(request) == {
        "grant_type": "password",
        "username": "user@example.test",
        "password": "secret",
    }
    # Credentials travel in the body: URLs end up in logs and error messages
    assert request.url == TOKEN_URL
    # The token endpoint is called without a bearer token
    assert "Authorization" not in request.headers


def test_request_tokens_invalid_grant_raises(mocked):
    mocked.post(TOKEN_URL, json={"error": "invalid_grant"}, status=401)
    api = FireServiceRota(BASE_URL, "user@example.test", "wrong")

    with pytest.raises(InvalidAuthError):
        api.request_tokens()


def test_request_tokens_other_error_returns_empty(mocked):
    mocked.post(TOKEN_URL, json={"error": "server_error"}, status=500)
    api = FireServiceRota(BASE_URL, "user@example.test", "secret")

    assert api.request_tokens() == {}


def test_refresh_tokens_replaces_tokens(mocked, api):
    new_tokens = {**TOKEN_INFO, "access_token": "access-2"}
    mocked.post(TOKEN_URL, json=new_tokens)

    assert api.refresh_tokens() == new_tokens

    request = mocked.calls[0].request
    assert _form(request) == {
        "grant_type": "refresh_token",
        "refresh_token": "refresh-1",
    }
    assert request.url == TOKEN_URL

    # Subsequent calls use the new access token
    mocked.get(f"{API}/skills", json=[])
    api.get_skills()
    assert (
        mocked.calls[1].request.headers["Authorization"] == "Bearer access-2"
    )


def test_refresh_tokens_without_tokens_makes_no_request(mocked):
    api = FireServiceRota(BASE_URL, "user@example.test", "secret")

    assert api.refresh_tokens() == {}
    assert len(mocked.calls) == 0


def test_refresh_tokens_invalid_grant_raises(mocked, api):
    mocked.post(TOKEN_URL, json={"error": "invalid_grant"}, status=401)

    with pytest.raises(InvalidAuthError):
        api.refresh_tokens()


def test_refresh_tokens_keeps_old_tokens_on_failure(mocked, api):
    mocked.post(TOKEN_URL, json={}, status=503)

    assert api.refresh_tokens() == TOKEN_INFO


# --- error handling -------------------------------------------------------


@pytest.mark.parametrize(
    ("error", "exception"),
    [
        ("token_invalid", InvalidTokenError),
        ("token_revoked", ExpiredTokenError),
        ("token_expired", ExpiredTokenError),
    ],
)
def test_401_maps_to_token_exception(mocked, api, error, exception):
    mocked.get(f"{API}/skills", json={"error": error}, status=401)

    with pytest.raises(exception):
        api.get_skills()


def test_401_with_unknown_error_returns_none(mocked, api):
    mocked.get(f"{API}/skills", json={"error": "other"}, status=401)

    assert api.get_skills() is None


@pytest.mark.parametrize("status", [403, 404, 500])
def test_http_error_returns_none_and_logs_status(mocked, api, status, caplog):
    mocked.get(f"{API}/skills", json={"error": "nope"}, status=status)

    assert api.get_skills() is None
    assert f"get skills: {status}: {{'error': 'nope'}}" in caplog.text


def test_http_error_with_non_json_body_returns_none(mocked, api):
    mocked.get(f"{API}/skills", body="<html>bad gateway</html>", status=502)

    assert api.get_skills() is None


def test_token_endpoint_error_is_logged(mocked, caplog):
    mocked.post(TOKEN_URL, json={"error": "server_error"}, status=500)

    FireServiceRota(BASE_URL, "user@example.test", "secret").request_tokens()

    assert "request tokens: 500: server_error" in caplog.text


def test_api_call_without_tokens_raises(mocked):
    api = FireServiceRota(BASE_URL, "user@example.test", "secret")

    with pytest.raises(InvalidTokenError):
        api.get_skills()


def test_repeated_token_errors_raise_fresh_exceptions(mocked, api):
    mocked.get(f"{API}/skills", json={"error": "token_expired"}, status=401)

    with pytest.raises(ExpiredTokenError) as first:
        api.get_skills()
    with pytest.raises(ExpiredTokenError) as second:
        api.get_skills()

    assert first.value is not second.value


def test_invalid_json_returns_none(mocked, api):
    mocked.get(f"{API}/skills", body="<html>oops</html>")

    assert api.get_skills() is None


@pytest.mark.parametrize(
    "error",
    [
        requests.exceptions.Timeout("slow"),
        requests.exceptions.ConnectionError("down"),
    ],
)
def test_network_error_returns_none(mocked, api, error):
    mocked.get(f"{API}/skills", body=error)

    assert api.get_skills() is None


def test_requests_carry_bearer_token_and_timeout(mocked, api):
    mocked.get(f"{API}/skills", json=[])

    api.get_skills()

    call = mocked.calls[0]
    assert call.request.headers["Authorization"] == "Bearer access-1"
    assert call.request.req_kwargs["timeout"] == 10


# --- endpoints ------------------------------------------------------------


def test_get_user(mocked, api):
    mocked.get(f"{API}/users/current.json", json=USER)

    assert api.get_user() == USER


def test_get_skills(mocked, api):
    skills = [{"id": 1, "name": "Driver"}]
    mocked.get(f"{API}/skills", json=skills)

    assert api.get_skills() == skills


def test_get_standby_function(mocked, api):
    mocked.get(f"{API}/standby_duty_functions/5", json={"name": "Chief"})

    assert api.get_standby_function(5) == {"name": "Chief"}


def test_get_incidents_passes_limit(mocked, api):
    mocked.get(f"{API}/incidents", json=[{"id": 1}])

    assert api.get_incidents(limit=3) == [{"id": 1}]
    assert _query(mocked.calls[0].request) == {"per_page": "3"}


@pytest.mark.parametrize(
    ("status", "expected"), [(True, "acknowledged"), (False, "rejected")]
)
def test_set_incident_response(mocked, api, status, expected):
    mocked.post(f"{API}/incidents/99/incident_responses", json={})

    api.set_incident_response(99, status)

    assert _query(mocked.calls[0].request) == {"status": expected}


def test_get_incident_response_returns_own_response(mocked, api):
    mocked.get(f"{API}/users/current.json", json=USER)
    mocked.get(
        f"{API}/incidents/99",
        json={
            "incident_responses": [
                {"user_id": 1, "status": "rejected"},
                {"user_id": 42, "status": "acknowledged"},
            ]
        },
    )

    assert api.get_incident_response(99) == {
        "user_id": 42,
        "status": "acknowledged",
    }


def test_get_incident_response_none_when_user_did_not_respond(mocked, api):
    mocked.get(f"{API}/users/current.json", json=USER)
    mocked.get(
        f"{API}/incidents/99",
        json={"incident_responses": [{"user_id": 1, "status": "rejected"}]},
    )

    assert api.get_incident_response(99) is None


def test_get_incident_response_none_on_error(mocked, api):
    mocked.get(f"{API}/users/current.json", json=USER)
    mocked.get(f"{API}/incidents/99", json={}, status=404)

    assert api.get_incident_response(99) is None


def test_get_schedules_uses_first_membership_and_day_window(mocked, api):
    mocked.get(f"{API}/users/current.json", json=USER)
    mocked.get(
        f"{API}/memberships/7/combined_schedule", json={"intervals": []}
    )

    assert api.get_schedules(datetime.timezone.utc) == {"intervals": []}

    query = _query(mocked.calls[1].request)
    start = datetime.datetime.strptime(
        query["start_time"], "%Y-%m-%dT%H:%M:%S%z"
    )
    end = datetime.datetime.strptime(query["end_time"], "%Y-%m-%dT%H:%M:%S%z")
    assert end - start == datetime.timedelta(days=1)
    assert (start.hour, start.minute, start.second) == (0, 0, 0)


def test_lookups_return_none_when_user_cannot_be_fetched(mocked, api):
    mocked.get(f"{API}/users/current.json", json={}, status=500)

    assert api.get_schedules(datetime.timezone.utc) is None
    assert api.get_incident_response(99) is None
    assert api.get_availability("Europe/Amsterdam") == {"available": False}


def test_get_schedules_fetches_user_only_once(mocked, api):
    mocked.get(f"{API}/users/current.json", json=USER)
    mocked.get(
        f"{API}/memberships/7/combined_schedule", json={"intervals": []}
    )

    api.get_schedules(datetime.timezone.utc)
    api.get_schedules(datetime.timezone.utc)

    urls = [call.request.url for call in mocked.calls]
    assert sum("users/current.json" in url for url in urls) == 1


# --- availability ---------------------------------------------------------

TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f%z"


def _interval(offset_start, offset_end, **extra):
    now = datetime.datetime.now().astimezone()
    return {
        "available": True,
        "start_time": (now + datetime.timedelta(hours=offset_start)).strftime(
            TIME_FORMAT
        ),
        "end_time": (now + datetime.timedelta(hours=offset_end)).strftime(
            TIME_FORMAT
        ),
        "detailed_availability": [],
        "assigned_function_ids": [],
        **extra,
    }


def _mock_schedule(mocked, intervals):
    mocked.get(f"{API}/users/current.json", json=USER)
    mocked.get(
        f"{API}/memberships/7/combined_schedule",
        json={"intervals": intervals},
    )


@pytest.mark.parametrize(
    ("detailed", "expected"),
    [
        (["standby_duty", "recurring"], "standby_duty"),
        (["exception", "recurring"], "exception"),
        (["recurring"], "recurring"),
        ([], "unknown"),
    ],
)
def test_get_availability_classifies_current_interval(
    mocked, api, detailed, expected
):
    _mock_schedule(mocked, [_interval(-1, 1, detailed_availability=detailed)])

    result = api.get_availability("Europe/Amsterdam")

    assert result["available"] is True
    assert result["type"] == expected


def test_get_availability_resolves_assigned_function(mocked, api):
    _mock_schedule(
        mocked,
        [
            _interval(
                -1,
                1,
                detailed_availability=["standby_duty"],
                assigned_function_ids=[5],
            )
        ],
    )
    mocked.get(f"{API}/standby_duty_functions/5", json={"name": "Chief"})

    result = api.get_availability("Europe/Amsterdam")

    assert result["assigned_function"] == "Chief"


def test_get_availability_survives_failing_function_lookup(mocked, api):
    _mock_schedule(mocked, [_interval(-1, 1, assigned_function_ids=[5])])
    mocked.get(f"{API}/standby_duty_functions/5", json={}, status=404)

    result = api.get_availability("Europe/Amsterdam")

    assert result["available"] is True
    assert "assigned_function" not in result


def test_get_availability_ignores_intervals_outside_now(mocked, api):
    _mock_schedule(mocked, [_interval(-3, -2), _interval(2, 3)])

    assert api.get_availability("Europe/Amsterdam") == {"available": False}


def test_get_availability_ignores_unavailable_interval(mocked, api):
    _mock_schedule(mocked, [_interval(-1, 1, available=False)])

    assert api.get_availability("Europe/Amsterdam") == {"available": False}


def test_get_availability_false_when_schedule_fails(mocked, api):
    mocked.get(f"{API}/users/current.json", json=USER)
    mocked.get(f"{API}/memberships/7/combined_schedule", json={}, status=500)

    assert api.get_availability("Europe/Amsterdam") == {"available": False}


# --- pagers ---------------------------------------------------------------


def test_get_pagers(mocked, api):
    mocked.get(f"{API}/pagers", json=[{"id": 3}])

    assert api.get_pagers() == [{"id": 3}]


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"address": "123"}, {"body": "hi", "address": "123"}),
        (
            {"addresses": ["123", "456"]},
            {"body": "hi", "addresses": ["123", "456"]},
        ),
        ({"confirmation": True}, {"body": "hi", "confirmation": True}),
        ({}, {"body": "hi", "confirmation": False}),
        (
            {"address": "123", "webhook_url": "https://hook.test"},
            {
                "body": "hi",
                "address": "123",
                "webhook_url": "https://hook.test",
            },
        ),
        # A single address wins over a list of addresses
        (
            {"address": "123", "addresses": ["456"]},
            {"body": "hi", "address": "123"},
        ),
    ],
)
def test_send_pager_message_body(mocked, api, kwargs, expected):
    mocked.post(f"{API}/pagers/3/messages", json={"id": 11})

    assert api.send_pager_message(3, "hi", **kwargs) == {"id": 11}
    assert json.loads(mocked.calls[0].request.body) == expected


def test_get_pager_message_status(mocked, api):
    mocked.get(
        f"{API}/pagers/3/messages/11",
        json={"acknowledgment_state": "manual"},
    )

    assert api.get_pager_message_status(3, 11) == {
        "acknowledgment_state": "manual"
    }
