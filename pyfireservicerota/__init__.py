"""Python 3 API wrapper for FireServiceRota and BrandweerRooster."""

import datetime
import json
import logging
import threading
from collections import deque
from typing import Optional

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
        """
        Initializes the FireServiceRota class.
        :param base_url: The base URL of the FireServiceRota API.
        :param username: The username for the FireServiceRota API.
        :param password: The password for the FireServiceRota API.
        :param token_info: The token information for the FireServiceRota API.
        """
        self._base_url = f"https://{base_url}"
        self._username = username
        self._password = password
        self._token_info = token_info
        self._user = None

    def request_tokens(self) -> dict:
        """
        Request new API tokens.
        :return: The token information.
        """
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
        """
        Refresh API tokens.
        :return: The token information.
        """
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
        """
        Get user information.
        :return: The user information.
        """
        self._user = self._request(
            "GET",
            endpoint="users/current.json",
            log_msg_action="get user",
            auth_request=False,
        )

        return self._user

    def get_schedules(self, tz):
        """
        Get user schedules.
        :param tz: The timezone of the user.
        :return: The user schedules.
        """
        if not self._user:
            self.get_user()

        today = datetime.datetime.now(tz)
        tomorrow = today + datetime.timedelta(days=1)

        id = self._user["memberships"][0]["id"]
        endpoint = f"memberships/{id}/combined_schedule"
        # fixme
        _LOGGER.debug(self._user["memberships"])

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
        """
        Get user skills.
        :return: The user skills.
        """
        response = self._request(
            "GET",
            endpoint="skills",
            log_msg_action="get skills",
            auth_request=False,
        )

        return response

    def get_standby_function(self, id):
        """
        Get standby function.
        :param id: The ID of the standby function.
        :return: The standby function.
        """
        endpoint = f"standby_duty_functions/{id}"

        response = self._request(
            "GET",
            endpoint=endpoint,
            log_msg_action="get standby function",
            auth_request=False,
        )

        return response

    def set_incident_response(self, id, status):
        """
        Set incident response.
        :param id: The ID of the incident.
        :param status: The status of the incident.
        """
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
        """
        Get incident response.
        :param id: The ID of the incident.
        :return: The incident response.
        """
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
        """
        Get user availability.
        :param tzstring: The timezone of the user.
        :return: The user availability.
        """
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
                                interval["assigned_function"] = (
                                    self.get_standby_function(func)["name"]
                                )

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
        """
        Make a request to the FireServiceRota API.
        :param method: The HTTP method of the request.
        :param endpoint: The endpoint of the request.
        :param log_msg_action: The action to log.
        :param params: The parameters of the request.
        :param body: The body of the request.
        :param auth_request: The authentication request.
        :return: The response of the request.
        """
        url = f"{self._base_url}/{endpoint}"
        headers = dict()
        response: Optional[requests.Response] = None

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
            if response is not None:
                try:
                    json_payload = response.json()
                except json.decoder.JSONDecodeError:
                    _LOGGER.error("Invalid JSON payload received")

            if auth_request:
                if (
                    response is not None
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
            elif response is not None and response.status_code == 401:
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
        except (
            RequestException,
            json.decoder.JSONDecodeError,
            ConnectionError,
        ) as err:
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
    """Class for communicating with the fireservicerota incidents API."""

    def __init__(self, on_incident=None):
        """
        Initializes the FireServiceRotaIncidents class.
        :param on_incident: function that gets called on received incident
        """
        self.on_incident = on_incident
        self.ws = None
        self.is_running = False

    def start(self, url):
        """
        Starts the websocket client and sets the running state to True.
        This method initializes the websocket client with the provided URL and
        starts the websocket client in a separate thread. It also initializes
        the `_recent_incidents` deque with a maximum length of 30.
        :param url: The URL of the websocket server.
        """
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
        self.is_running = True

    def stop(self):
        """
        Stops the websocket client and sets the running state to False.
        This method closes the websocket connection and logs a debug message
        indicating that the websocket client has been stopped. It also updates
        the `is_running` attribute to False.
        """
        self.ws.close()
        _LOGGER.debug("Websocket client stopped")
        self.is_running = False

    def __on_open(self, ws):
        """
        This method is called when the websocket connection is opened.
        :param ws: The websocket instance.
        """
        _LOGGER.debug("Websocket open")

    def __on_close(self, ws, close_status_code, close_msg):
        """
        This method is called when the websocket connection is closed.
        :param ws: The websocket instance.
        :param close_status_code: The status code of the close message.
        :param close_msg: The close message.
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
        """
        This method is called when a message is received from the websocket.
        :param ws: The websocket instance.
        :param message: The message received from the websocket.
        """
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
