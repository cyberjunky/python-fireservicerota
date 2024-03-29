"""Python 3 API wrapper for FireServiceRota and BrandweerRooster."""
import datetime
import json
import logging
import threading
from collections import deque

import oauthlib.oauth2
import pytz
import requests
import websocket
from requests.exceptions import HTTPError, RequestException, Timeout

_LOGGER = logging.getLogger("fireservicerota")


class FireServiceRota(object):
    """Class for communicating with the fireservicerota API."""

    def __init__(
        self,
        base_url=None,
        username: str = "",
        password: str = "",
        token_info: dict = {},
    ):
        """Init module"""
        self._base_url = f"https://{base_url}"
        self._username = username
        self._password = password
        self._token_info = token_info
        self._user = None

    def request_tokens(self) -> dict:
        """Request API tokens."""

        oauth_client = oauthlib.oauth2.LegacyApplicationClient(client_id=None)
        request_body = oauth_client.prepare_request_body(
            username=self._username, password=self._password
        )

        try:
            token_info = self._request(
                "POST",
                endpoint="oauth/token",
                log_msg_action="request tokens",
                params=request_body,
                auth_request=True,
            )
            if token_info:
                self._token_info = token_info

            _LOGGER.debug(
                f"Obtained tokens: access {self._token_info['access_token']}, "
                f"refresh {self._token_info['refresh_token']}"
            )
        except (KeyError, TypeError) as err:
            _LOGGER.debug(f"Error obtaining tokens: {err}")

        return self._token_info

    def refresh_tokens(self) -> dict:
        """Refresh existing API tokens."""

        if not self._token_info:
            return self._token_info

        oauth_client = oauthlib.oauth2.LegacyApplicationClient(client_id=None)
        request_body = oauth_client.prepare_refresh_body(
            refresh_token=self._token_info["refresh_token"]
        )
        try:
            token_info = self._request(
                "POST",
                endpoint="oauth/token",
                log_msg_action="refresh tokens",
                params=request_body,
                auth_request=True,
            )

            if token_info:
                self._token_info = token_info
            _LOGGER.debug("Refreshed access tokens")
        except (KeyError, TypeError) as err:
            _LOGGER.debug(f"Error refreshing tokens: {err}")

        return self._token_info

    def get_user(self):
        """Get user data."""

        self._user = self._request(
            "GET",
            endpoint="users/current.json",
            log_msg_action="get user",
            auth_request=False,
        )

        return self._user

    def get_schedules(self, tz):
        """Get user schedules."""

        if not self._user:
            self.get_user()

        today = datetime.datetime.now(tz)
        tomorrow = today + datetime.timedelta(days=1)
        id = self._user["memberships"][0]["id"]
        endpoint = f"memberships/{id}/combined_schedule"

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
            endpoint="skills",
            log_msg_action="get skills",
            auth_request=False,
        )

        return response

    def get_standby_function(self, id):
        """Get standby function."""

        endpoint = f"standby_duty_functions/{id}"

        response = self._request(
            "GET",
            endpoint=endpoint,
            log_msg_action="get standby function",
            auth_request=False,
        )

        return response

    def set_incident_response(self, id, status):
        """Set incident response for one incident."""

        endpoint = f"incidents/{id}/incident_responses"

        if status:
            params = {"status": "acknowledged"}
        else:
            params = {"status": "rejected"}

        self._request(
            "POST",
            endpoint=endpoint,
            log_msg_action="set incident response",
            params=params,
            auth_request=False,
        )

    def get_incident_response(self, id):
        """Get status of incident response for one incident."""

        if not self._user:
            self.get_user()

        endpoint = f"incidents/{id}"

        response = self._request(
            "GET",
            endpoint=endpoint,
            log_msg_action="get incident response",
            auth_request=False,
        )

        if response:
            for r in response["incident_responses"]:
                if self._user["id"] == r["user_id"]:
                    return r

        return None

    def get_availability(self, tzstring):
        """Get user availability."""
        tz = pytz.timezone(tzstring)
        response = self.get_schedules(tz)

        if response:
            for interval in response["intervals"]:
                if interval["available"]:
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
        params: dict = {},
        body: dict = {},
        auth_request: bool = False,
    ) -> dict | None:
        """Makes a request to the fireservicerota API."""
        url = f"{self._base_url}/{endpoint}"
        headers = dict()

        if not auth_request:
            url = f"{self._base_url}/api/v2/{endpoint}"
            headers = {
                "Content-Type": "application/json;charset=UTF-8",
                "Authorization": f"Bearer {self._token_info['access_token']}",
            }

        _LOGGER.debug(
            f"Making request to {endpoint} endpoint to {log_msg_action}, "
            f"url: {url}, headers: {headers}, params: {params}, body: {body}"
        )

        try:
            response = requests.request(
                method,
                url,
                headers=headers,
                params=params,
                json=body,
                timeout=10,
            )

            try:
                log_msg = response.json()

            except requests.exceptions.SSLError:
                _LOGGER.error("SSL error occurred")
            except json.decoder.JSONDecodeError:
                _LOGGER.error("Invalid JSON payload received")

            _LOGGER.debug(
                f"Request response: {response.status_code}: {log_msg}"
            )

            response.raise_for_status()
            return response.json()
        except HTTPError as err:
            json_payload = {}
            try:
                json_payload = response.json()
            except json.decoder.JSONDecodeError:
                _LOGGER.error("Invalid JSON payload received")

            if auth_request:
                if (
                    response
                    and response.status_code == 401
                    and json_payload.get("error") == "invalid_grant"
                ):
                    raise InvalidAuthError(
                        "Invalid credentials or refresh token invalid"
                    )
                else:
                    if response:
                        _LOGGER.error(
                            f"Error requesting authorization: "
                            f"{response.status_code}: {json_payload}"
                        )
            elif response and response.status_code == 401:
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
                        f"Error {err} while attempting to {log_msg_action}"
                    )
            else:
                if response:
                    _LOGGER.error(
                        f"Error while attempting to {log_msg_action}: "
                        f"{response.status_code}: {json_payload}"
                    )
                else:
                    _LOGGER.error(
                        f"Error {err} connecting while attempting to {log_msg_action}"
                    )
        except Timeout:
            _LOGGER.error(
                f"Connection timed out while attempting to {log_msg_action}, "
                f"possible connectivity outage"
            )
        except (RequestException, json.decoder.JSONDecodeError) as err:
            if response:
                _LOGGER.error(
                    f"Error connecting while attempting to {log_msg_action}, "
                    f"{response.status_code}: {json_payload}"
                )
            else:
                _LOGGER.error(
                    f"Error {err} connecting while attempting to {log_msg_action}"
                )
        return None


class FireServiceRotaIncidents:
    is_running = True

    def __init__(self, on_incident=None):
        """
        :param on_incident: function that gets called on received incident
        """
        self.on_incident = on_incident
        self.ws = None

    def start(self, url):
        self._url = url
        self._recent_incidents = deque(maxlen=30)

        _LOGGER.debug("Websocket client start")

        self.ws = websocket.WebSocketApp(
            self._url,
            on_open=self.__on_open,
            on_error=self.__on_error,
            on_message=self.__on_message,
            on_close=self.__on_close,
        )

        self.wst = threading.Thread(target=lambda: self.ws.run_forever())
        self.wst.daemon = True
        self.wst.start()

    def stop(self):
        """
        close websocket
        """
        self.is_running = False
        self.ws.close()
        _LOGGER.debug("Websocket client stopped")

    def __on_open(self, ws):
        _LOGGER.debug("Websocket open")

    def __on_close(self, ws, close_status_code, close_msg):
        """
        On Close Listener
        """
        if self.is_running:
            _LOGGER.debug("Websocket restarted after close")

            self.ws = websocket.WebSocketApp(
                self._url,
                on_open=self.__on_open,
                on_error=self.__on_error,
                on_message=self.__on_message,
                on_close=self.__on_close,
            )
            self.wst = threading.Thread(target=lambda: self.ws.run_forever())
            self.wst.daemon = True
            self.wst.start()

    def __on_message(self, ws, message):
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
                    """mark new and update messages"""
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
                self.ws.send(
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
                _LOGGER.debug("Successfully subscribed to incidents channel")
            elif message["type"] == "ping":
                pass
            else:
                _LOGGER.debug(f"Received unknown type: {message}")
        except Exception as e:
            _LOGGER.exception(e)

    def __on_error(self, ws, error):
        """
        On Error listener
        :param error:
        """
        _LOGGER.debug("Websocket error: %s", error)


class ExpiredTokenError(Exception):
    """Raised when fireservicerota API returns a code indicating expired tokens."""

    pass


class InvalidTokenError(Exception):
    """Raised when fireservicerota API returns a code indicating invalid tokens."""

    pass


class InvalidAuthError(Exception):
    """Raised when fireservicerota API returns a code indicating invalid credentials."""

    pass
