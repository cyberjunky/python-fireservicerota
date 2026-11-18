"""Python 3 API wrapper for FireServiceRota and BrandweerRooster."""

import datetime
import json
import logging
import threading
import time
from collections import deque

import oauthlib.oauth2
import pytz
import requests
import websocket
from requests.exceptions import HTTPError, RequestException, Timeout

_LOGGER = logging.getLogger("fireservicerota")


class FireServiceRota:
    """Class for communicating with the fireservicerota API."""

    def __init__(
        self,
        base_url=None,
        username: str = "",
        password: str = "",
        token_info: dict | None = None,
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
        self._token_info = token_info or {}
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
            if isinstance(token_info, dict):
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

            if isinstance(token_info, dict):
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

        membership_id = self._user["memberships"][0]["id"]
        endpoint = f"memberships/{membership_id}/combined_schedule"

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

    def get_incidents(self, limit: int = 10) -> list | None:
        """
        Get recent incidents.
        :param limit: Maximum number of incidents to return.
        :return: A list of incident dicts, or None on error.
        """
        return self._request(  # type: ignore[return-value]
            "GET",
            endpoint="incidents",
            log_msg_action="get incidents",
            params={"per_page": limit},
            auth_request=False,
        )

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

    def get_pagers(self) -> list | None:
        """
        Get all pagers linked to the authenticated user.
        :return: A list of pager dicts, or None on error.
        """
        return self._request(  # type: ignore[return-value]
            "GET",
            endpoint="pagers",
            log_msg_action="get pagers",
            auth_request=False,
        )

    def send_pager_message(
        self,
        pager_id: int,
        message: str,
        address: str | None = None,
        addresses: list | None = None,
        confirmation: bool = False,
        webhook_url: str | None = None,
    ) -> dict | None:
        """
        Send a text message to a specific pager.
        :param pager_id: The pager id as returned by get_pagers().
        :param message: Text to display on the pager.
        :param address: Pager capcode address. Exactly one of address,
            addresses, or confirmation must be provided.
        :param addresses: List of pager capcode addresses.
        :param confirmation: Send using the pager's own registered address.
        :param webhook_url: Optional URL for delivery-status callbacks.
        :return: A dict with id, body, pager_id, acknowledgment_state, address, addresses, or None on error.
        """
        body: dict = {"body": message}
        if address:
            body["address"] = address
        elif addresses:
            body["addresses"] = addresses
        else:
            body["confirmation"] = confirmation
        if webhook_url:
            body["webhook_url"] = webhook_url

        return self._request(  # type: ignore[return-value]
            "POST",
            endpoint=f"pagers/{pager_id}/messages",
            log_msg_action="send pager message",
            body=body,
            auth_request=False,
        )

    def get_pager_message_status(
        self,
        pager_id: int,
        message_id: int,
    ) -> dict | None:
        """
        Poll delivery status of a previously sent pager message.
        :param pager_id: The pager id.
        :param message_id: The id returned by send_pager_message().
        :return: A dict with acknowledgment_state (e.g. "automatic", "manual", "none"), or None on error.
        """
        return self._request(  # type: ignore[return-value]
            "GET",
            endpoint=f"pagers/{pager_id}/messages/{message_id}",
            log_msg_action="get pager message status",
            auth_request=False,
        )

    def _request(
        self,
        method: str,
        endpoint: str,
        log_msg_action: str,
        params: dict | None = None,
        body: dict | None = None,
        auth_request: bool = False,
    ) -> dict | list | None:
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
        response: requests.Response | None = None
        json_payload: dict = {}
        params = params or {}

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
                json=body or None,
                timeout=10,
            )

            _LOGGER.debug(
                "Request response: %s: %s",
                response.status_code,
                response.json(),
            )

            response.raise_for_status()
            return response.json()
        except HTTPError as err:
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


# Incidents are not replayed by the server, so every second offline counts:
# the first reconnect is immediate and retries never wait longer than this.
RECONNECT_DELAY_MAX = 5
# A connection that lived shorter than this does not reset the retry delay,
# so a server that accepts and instantly drops us is not hammered.
STABLE_CONNECTION_SECONDS = 10


class FireServiceRotaIncidents:
    """Class for communicating with the fireservicerota incidents API."""

    def __init__(
        self,
        on_incident=None,
        ping_interval: int = 6,
        ping_timeout: int = 4,
        connect_timeout: int = 5,
        on_connect_failed=None,
    ):
        """
        Initializes the FireServiceRotaIncidents class.
        :param on_incident: function that gets called on received incident
        :param ping_interval: seconds of silence after which the connection
            is probed with a ping; the server sends a heartbeat every 3
            seconds, so a healthy connection is never silent this long
        :param ping_timeout: seconds to wait for a reply to that ping before
            the connection is considered dead
        :param connect_timeout: seconds to wait for the connection and its
            handshake to complete
        :param on_connect_failed: function without arguments that gets
            called, from the listener thread, each time a connection attempt
            ends without the server welcoming us; an expired access token
            is a common cause, so this is the moment to refresh it and
            call `start` with a new URL
        """
        self.on_incident = on_incident
        self.on_connect_failed = on_connect_failed
        self.ws: websocket.WebSocket | None = None
        self.wst: threading.Thread | None = None
        self.is_running = False
        self.ping_interval = ping_interval
        self.ping_timeout = ping_timeout
        self.connect_timeout = connect_timeout
        self._url: str | None = None
        self._recent_incidents: deque = deque(maxlen=30)
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

    def start(
        self,
        url,
    ):
        """
        Starts the websocket client and sets the running state to True.
        The client runs in a separate thread and keeps reconnecting, with an
        increasing delay, until `stop` is called.
        :param url: The URL of the websocket server.
        """
        if self.is_running:
            self.stop()

        self._url = url
        self._recent_incidents = deque(maxlen=30)

        _LOGGER.debug("Websocket client start")

        # Every run gets its own stop event, so a thread that is still
        # winding down after stop() can never be revived by a later start().
        stop_event = threading.Event()
        self._stop_event = stop_event
        self.is_running = True
        self.wst = threading.Thread(
            target=self._run,
            args=(url, stop_event),
            name="fireservicerota-incidents",
            daemon=True,
        )
        self.wst.start()

    def stop(self):
        """
        Stops the websocket client and sets the running state to False.
        This method closes the websocket connection and prevents any further
        reconnect attempts.
        """
        self.is_running = False
        self._stop_event.set()
        with self._lock:
            ws = self.ws
        if ws is not None:
            try:
                # abort() wakes up the listener thread blocked in recv
                ws.abort()
            except OSError as err:
                _LOGGER.debug("Websocket abort failed: %s", err)
        _LOGGER.debug("Websocket client stopped")

    def _run(self, url: str, stop_event: threading.Event) -> None:
        """Connect, listen and reconnect until stopped."""
        delay = 0

        while not stop_event.is_set():
            ws = None
            connected_at = None
            welcomed = False
            try:
                # The timeout also covers the TLS and websocket handshakes;
                # without it a stalled handshake blocks this thread forever.
                ws = websocket.create_connection(
                    url, timeout=self.connect_timeout
                )
                with self._lock:
                    self.ws = ws
                _LOGGER.debug("Websocket open")
                connected_at = time.monotonic()
                if not stop_event.is_set():
                    welcomed = self._listen(ws, stop_event)
            except (websocket.WebSocketException, OSError) as err:
                if not stop_event.is_set():
                    _LOGGER.debug("Websocket error: %s", err)
            finally:
                with self._lock:
                    if self.ws is ws:
                        self.ws = None
                if ws is not None:
                    ws.shutdown()

            if stop_event.is_set():
                break

            if (
                welcomed
                and connected_at is not None
                and time.monotonic() - connected_at
                >= STABLE_CONNECTION_SECONDS
            ):
                delay = 0

            if not welcomed and self.on_connect_failed:
                try:
                    self.on_connect_failed()
                except Exception as e:
                    _LOGGER.exception(e)
                if stop_event.is_set():
                    break

            _LOGGER.info(
                "Websocket connection lost, reconnecting in %s seconds", delay
            )
            stop_event.wait(delay)
            delay = min(max(delay * 2, 1), RECONNECT_DELAY_MAX)

    def _listen(
        self, ws: websocket.WebSocket, stop_event: threading.Event
    ) -> bool:
        """
        Receive messages until the connection is closed or found dead.
        :return: True if the server welcomed us on this connection.
        """
        welcomed = False
        awaiting_pong = False
        ws.settimeout(self.ping_interval or None)

        while not stop_event.is_set():
            try:
                opcode, frame = ws.recv_data_frame(control_frame=True)
            except websocket.WebSocketTimeoutException:
                if awaiting_pong:
                    _LOGGER.debug("Websocket ping timed out")
                    return welcomed
                try:
                    ws.ping()
                except (websocket.WebSocketException, OSError) as err:
                    _LOGGER.debug("Websocket error: %s", err)
                    return welcomed
                awaiting_pong = True
                ws.settimeout(self.ping_timeout)
                continue
            except (websocket.WebSocketException, OSError) as err:
                if not stop_event.is_set():
                    _LOGGER.debug("Websocket error: %s", err)
                return welcomed

            if awaiting_pong:
                awaiting_pong = False
                ws.settimeout(self.ping_interval or None)

            if opcode == websocket.ABNF.OPCODE_CLOSE:
                _LOGGER.debug("Websocket closed by server")
                return welcomed
            if opcode == websocket.ABNF.OPCODE_TEXT:
                if self.__on_message(ws, frame.data.decode("utf-8")):
                    welcomed = True

        return welcomed

    def __on_message(self, ws, message) -> bool:
        """
        This method is called when a message is received from the websocket.
        :param ws: The websocket instance.
        :param message: The message received from the websocket.
        :return: True if the message was the server's welcome.
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
                    # mark new vs update messages
                    incident_id = incident["id"]
                    if incident_id not in self._recent_incidents:
                        self._recent_incidents.append(incident_id)
                        incident["trigger"] = "new"
                        _LOGGER.debug("New incident received")
                    else:
                        incident["trigger"] = "update"
                        _LOGGER.debug("Incident update received")
                    if self.on_incident:
                        self.on_incident(incident)
                else:
                    _LOGGER.debug(f"Malformed data received\n{message}")
            elif message["type"] == "welcome":
                _LOGGER.debug("Subscribing to the incidents channel")
                ws.send(
                    json.dumps(
                        {
                            "command": "subscribe",
                            "identifier": json.dumps(
                                {"channel": "IncidentNotificationsChannel"}
                            ),
                        }
                    )
                )
                return True
            elif message["type"] == "confirm_subscription":
                _LOGGER.debug("Successfully subscribed to incidents channel")
        except Exception as e:
            _LOGGER.exception(e)
        return False


class ExpiredTokenError(Exception):
    """Raised when fireservicerota API returns a code indicating expired tokens."""

    pass


class InvalidTokenError(Exception):
    """Raised when fireservicerota API returns a code indicating invalid tokens."""

    pass


class InvalidAuthError(Exception):
    """Raised when fireservicerota API returns a code indicating invalid credentials."""

    pass
