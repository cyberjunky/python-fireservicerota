"""Python 3 API wrapper for FireServiceRota and BrandweerRooster."""
import datetime
import json
import logging
from collections import deque
from threading import Thread
from typing import Optional

import oauthlib.oauth2
import requests
import websocket
from requests.exceptions import HTTPError, RequestException, Timeout

from .const import (
    FSR_DEFAULT_TIMEOUT,
    FSR_ENDPOINT_DUTY_STANDBY_FUNCTION,
    FSR_ENDPOINT_INCIDENT_RESPONSES,
    FSR_ENDPOINT_INCIDENTS,
    FSR_ENDPOINT_MEMBERSHIPS,
    FSR_ENDPOINT_SKILLS,
    FSR_ENDPOINT_TOKEN,
    FSR_ENDPOINT_USER,
)
from .errors import ExpiredTokenError, InvalidAuthError, InvalidTokenError

_LOGGER = logging.getLogger("pyfireservicerota")


class FireServiceRota(object):
    """Class for communicating with the fireservicerota API."""

    def __init__(
        self,
        base_url=None,
        username: str = None,
        password: str = None,
        token_info: dict = None,
    ):
        """Init module."""
        self._base_url = base_url
        self._username = username
        self._password = password
        self._token_info = token_info
        self._user = None

    def request_tokens(self) -> bool:
        """Request API tokens."""
        oauth_client = oauthlib.oauth2.LegacyApplicationClient(client_id=None)
        request_body = oauth_client.prepare_request_body(
            username=self._username, password=self._password
        )
        response = self._request(
            "POST",
            endpoint=FSR_ENDPOINT_TOKEN,
            log_msg_action="request tokens",
            params=str.encode(request_body),
            auth_request=True,
        )

        try:
            self._token_info = response
            _LOGGER.debug(
                f"Obtained tokens: access {self._token_info['access_token']}, "
                f"refresh {self._token_info['refresh_token']}"
            )
            return self._token_info
        except (KeyError, TypeError) as err:
            _LOGGER.debug(f"Error obtaining tokens: {err}")
            return False

    def refresh_tokens(self) -> bool:
        """Refresh existing oauth tokens."""
        if not self._token_info:
            return

        oauth_client = oauthlib.oauth2.LegacyApplicationClient(client_id=None)
        request_body = oauth_client.prepare_refresh_body(
            refresh_token=self._token_info["refresh_token"]
        )
        response = self._request(
            "POST",
            endpoint=FSR_ENDPOINT_TOKEN,
            log_msg_action="refresh tokens",
            params=str.encode(request_body),
            auth_request=True,
        )

        try:
            self._token_info = response
            _LOGGER.debug("Refreshed access tokens.")
            return self._token_info
        except (KeyError, TypeError) as err:
            _LOGGER.debug(f"Error refreshing tokens: {err}")
            return False

    def _get_userid(self):
        """Get user data."""
        self._user = self._request(
            "GET",
            endpoint=FSR_ENDPOINT_USER,
            log_msg_action="get userid",
            auth_request=False,
        )

    def get_schedules(self):
        """Get user schedules."""
        if not self._user:
            self._get_userid()

        today = datetime.datetime.now().astimezone()
        tomorrow = today + datetime.timedelta(days=1)
        id = self._user["memberships"][0]["id"]
        endpoint = FSR_ENDPOINT_MEMBERSHIPS.format(id)

        params = {
            "start_time": today.strftime("%Y-%m-%dT00:00:00%z"),
            "end_time": tomorrow.strftime("%Y-%m-%dT00:00:00%z"),
        }

        response = self._request(
            "GET",
            endpoint=endpoint,
            params=params,
            log_msg_action="get schedule memberships",
            auth_request=False,
        )

        return response

    def get_skills(self):
        """Get skills."""
        response = self._request(
            "GET",
            endpoint=FSR_ENDPOINT_SKILLS,
            log_msg_action="get skills",
            auth_request=False,
        )

        return response

    def get_standby_function(self, id):
        """Get standby function."""
        endpoint = FSR_ENDPOINT_DUTY_STANDBY_FUNCTION.format(id)

        response = self._request(
            "GET",
            endpoint=endpoint,
            log_msg_action="get standby function",
            auth_request=False,
        )

        return response

    def set_incident_response(self, id, status):
        """Set incident response for one incident."""
        endpoint = FSR_ENDPOINT_INCIDENT_RESPONSES.format(id)

        if status:
            params = {"status": "acknowledged"}
        else:
            params = {"status": "rejected"}

        self._request(
            "POST",
            endpoint=endpoint,
            params=params,
            log_msg_action="set incident response",
            auth_request=False,
        )

    def get_incident_response(self, id):
        """Get status of incident response for one incident."""
        endpoint = FSR_ENDPOINT_INCIDENTS.format(id)

        response = self._request(
            "GET",
            endpoint=endpoint,
            log_msg_action="get incident response",
            auth_request=False,
        )

        for r in response["incident_responses"]:
            if self._user["id"] == r["user_id"]:
                return r

        return None

    def get_availability(self):
        """Get user availablity."""
        response = self.get_schedules()

        if response:
            for interval in response["intervals"]:
                if interval["available"] is True:
                    now = datetime.datetime.now().astimezone()
                    if now > datetime.datetime.strptime(
                        interval["start_time"], "%Y-%m-%dT%H:%M:%S.%f%z"
                    ) and now < datetime.datetime.strptime(
                        interval["end_time"], "%Y-%m-%dT%H:%M:%S.%f%z"
                    ):
                        if "standby_duty" in interval["detailed_availability"]:
                            interval["type"] = "standby_duty"
                        elif "exception" in interval["detailed_availability"]:
                            interval["type"] = "exception"
                        elif "recurring" in interval["detailed_availability"]:
                            interval["type"] = "recurring"
                        else:
                            interval["type"] = "unknown"

                        if interval["assigned_function_ids"]:
                            for func in interval["assigned_function_ids"]:
                                interval[
                                    "assigned_function"
                                ] = self.get_standby_function(func)["name"]

                        return interval

        return {"available": False}

    def _request(
        self,
        method: str,
        endpoint: str,
        log_msg_action: str,
        params: dict = None,
        body: dict = None,
        auth_request: bool = False,
    ) -> Optional[str]:
        """Make a request to the fireservicerota API."""
        url = f"{self._base_url}/{endpoint}"
        headers = dict()

        if not auth_request:
            url = f"{self._base_url}/api/v2/{endpoint}"
            headers = {
                "Content-Type": "application/json;charset=UTF-8",
                "Authorization": f"Bearer {self._token_info['access_token']}",
            }

        _LOGGER.debug(
            f"Making request to {endpoint} endpoint to {log_msg_action}: "
            f"url: {url}, headers: {headers}, params: {params}, body: {body}"
        )

        try:
            response = requests.request(
                method,
                url,
                headers=headers,
                params=params,
                json=body,
                timeout=FSR_DEFAULT_TIMEOUT,
            )

            try:
                log_msg = response.json()
            except ValueError:
                log_msg = response.text
            _LOGGER.debug(f"Response: {response.status_code}: {log_msg}")

            response.raise_for_status()
            return response.json()
        except HTTPError:
            json_payload = {}
            try:
                json_payload = response.json()
            except json.decoder.JSONDecodeError:
                _LOGGER.debug("Invalid JSON payload received")

            if auth_request:
                if (
                    response.status_code == 401
                    and json_payload.get("error") == "invalid_grant"
                ):
                    raise InvalidAuthError(
                        "Invalid credentials or refresh token invalid"
                    )
                else:
                    _LOGGER.error(
                        f"Error requesting authorization: "
                        f"{response.status_code}: {json_payload}"
                    )
            elif response.status_code == 401:
                error = json_payload.get("error")
                if error == "token_invalid":
                    raise InvalidTokenError(
                        "Access token invalid; re-authentication required"
                    )
                elif error == "token_revoked":
                    raise ExpiredTokenError(
                        "Access token revoked; token refresh required"
                    )
                elif error == "token_expired":
                    raise ExpiredTokenError(
                        "Access token expired; token refresh required"
                    )
                else:
                    _LOGGER.error(
                        f"Error while attempting to {log_msg_action}: {error}:"
                        f"{json_payload.get('status', {}).get('msg', 'Unknown error')}"
                    )
            else:
                _LOGGER.error(
                    f"Error while attempting to {log_msg_action}: "
                    f"{response.status_code}: {json_payload}"
                )
        except Timeout:
            _LOGGER.error(
                f"Connection timed out while attempting to {log_msg_action}. "
                f"Possible connectivity outage."
            )
        except (RequestException, json.decoder.JSONDecodeError):
            _LOGGER.error(
                f"Error connecting while attempting to {log_msg_action}. "
                f"{response.status_code}: {json_payload}"
            )
        return None


class FireServiceRotaIncidents(Thread, websocket.WebSocketApp):
    """Connect to websocket and listen for incidents."""

    def __init__(self, url, on_incident=None, on_close=None):
        """Params url, on_incident, on_close."""
        self._url = url
        self.on_close = on_close

        Thread.__init__(self)
        websocket.WebSocketApp.__init__(
            self,
            url,
            on_open=self.on_open,
            on_message=self.on_message,
            on_close=self.on_close,
        )

        self.on_incident = on_incident
        self._recent_incidents = deque(maxlen=30)

    def on_open(self):
        """Websocket client connection is opened."""
        _LOGGER.debug("Websocket open")

    def on_error(self, error):
        """Websocket client connection has an error."""
        _LOGGER.debug("Websocket open %s", error)

    def on_message(self, message):
        """Websocket client received an incident."""
        _LOGGER.debug("Websocket data:" + message)
        try:
            message = json.loads(message)
            if "type" not in message:
                if (
                    "identifier" in message
                    and json.loads(message["identifier"])["channel"]
                    == "IncidentNotificationsChannel"
                ):
                    incident = message["message"]
                    """Mark new and updated messages"""
                    incident_id = incident["id"]
                    if incident_id not in self._recent_incidents:
                        self._recent_incidents.append(incident_id)
                        incident["trigger"] = "new"
                        _LOGGER.debug("New incident received")
                    else:
                        incident["trigger"] = "update"
                        _LOGGER.debug("Incident update received")
                    self.on_incident(incident)
                else:
                    _LOGGER.debug(f"Malformed data received\n{message}")
            elif message["type"] == "welcome":
                _LOGGER.debug("Subscribing to the incidents channel")
                self.send(
                    json.dumps(
                        {
                            "command": "subscribe",
                            "identifier": json.dumps(
                                {"channel": "IncidentNotificationsChannel"}
                            ),
                        }
                    )
                )
            elif message["type"] == "confirm_subscription":
                _LOGGER.debug("Succesfully subscribed to incidents channel")
            elif message["type"] == "ping":
                pass
            else:
                _LOGGER.debug(f"Received unknown type: {message}")
        except Exception as e:
            _LOGGER.exception(e)

    def run_forever(
        self, sockopt=None, sslopt=None, ping_interval=0, ping_timeout=None
    ):
        """Call listener forever."""
        #        websocket.enableTrace(True)
        websocket.WebSocketApp.run_forever(
            self,
            sockopt=sockopt,
            sslopt=sslopt,
            ping_interval=ping_interval,
            ping_timeout=ping_timeout,
        )
