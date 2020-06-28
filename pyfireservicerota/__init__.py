"""Python 3 API wrapper for FireServiceRota and BrandweerRooster."""
from typing import Optional
import json
import time
from collections import deque
import oauthlib.oauth2
import websocket
import requests
from threading import Thread
import datetime

from typing import Optional
from requests.exceptions import HTTPError, RequestException, Timeout

from .const import (
    _LOGGER,
    FSR_DEFAULT_TIMEOUT,
    FSR_ENDPOINT_TOKEN,
    FSR_ENDPOINT_USER,
    FSR_ENDPOINT_MEMBERSHIPS,
    FSR_ENDPOINT_SKILLS,
    FSR_ENDPOINT_DUTY_STANDBY_FUNCTIONS,
    FSR_ENDPOINT_DUTY_STANDBY_FUNCTION,
)
from .errors import FireServiceRotaError, InvalidAuthError, ExpiredTokenError, InvalidTokenError


class FireServiceRota(object):
    """Class for communicating with the fireservicerota API."""

    def __init__(self, base_url = None, username: str = None, password: str = None, token_info: dict = None):
        """Init module"""

        self._base_url = base_url
        self._username = username
        self._password = password
        self._token_info = token_info

        self._user = None


    def request_tokens(self) -> bool:
        """Get API tokens."""

        oauth_client = oauthlib.oauth2.LegacyApplicationClient(client_id=None)
        request_body = oauth_client.prepare_request_body(
                 username=self._username, password=self._password)
        response = self._request('POST', endpoint=FSR_ENDPOINT_TOKEN, log_msg_action='request tokens',
                 params=str.encode(request_body), auth_request=True)

        try:
            self._token_info = response
            _LOGGER.debug(f"Obtained tokens: access {self._token_info['access_token']}, "
                          f"refresh {self._token_info['refresh_token']}")
            return self._token_info
        except (KeyError, TypeError) as err:
            _LOGGER.debug(f"Error obtaining tokens: {err}")
            return False


    def refresh_tokens(self) -> bool:
        """Refresh API tokens."""

        if not self._token_info:
           return

        oauth_client = oauthlib.oauth2.LegacyApplicationClient(client_id=None)
        request_body = oauth_client.prepare_refresh_body(
                 refresh_token=self._token_info['refresh_token'])
        response = self._request('POST', endpoint=FSR_ENDPOINT_TOKEN, log_msg_action='refresh tokens',
                 params=str.encode(request_body), auth_request=True)

        try:
            self._token_info = response
            _LOGGER.debug(f"Refreshed tokens: access {self._token_info['access_token']}, "
                          f"refresh {self._token_info['refresh_token']}")
            return self._token_info
        except (KeyError, TypeError) as err:
            _LOGGER.debug(f"Error refreshing tokens: {err}")
            return False


    def get_userid(self):
        """Get user data."""

        self._user = self._request('GET', endpoint=FSR_ENDPOINT_USER, log_msg_action='get userid',
                 auth_request=False)

        _LOGGER.debug(f"Userid data: {self._user}")


    def get_schedules(self):
        """Get user schedules."""

        if not self._user:
            self.get_userid()

        today = datetime.date.today()
        tomorrow = today + datetime.timedelta(days = 1)
        id =  self._user['memberships'][0]['id']
        url = FSR_ENDPOINT_MEMBERSHIPS.format(id, today, tomorrow)

        response = self._request('GET', endpoint=url, log_msg_action='get memberships',
                 auth_request=False)

        return response


    def get_skills(self):
        """Get skills."""

        url = FSR_ENDPOINT_SKILLS

        response = self._request('GET', endpoint=url, log_msg_action='get skills',
                 auth_request=False)

        return response


    def get_standby_function(self, id):
        """Get standby function."""

        url = FSR_ENDPOINT_DUTY_STANDBY_FUNCTION.format(id)

        response = self._request('GET', endpoint=url, log_msg_action='get standby function',
                 auth_request=False)

        return response


    def get_availability(self):
        """Get user availablity."""

        if not self._user:
            self.get_userid()

        today = datetime.date.today()
        tomorrow = today + datetime.timedelta(days = 1)

        id =  self._user['memberships'][0]['id']
        url = FSR_ENDPOINT_MEMBERSHIPS.format(id, today, tomorrow)

        response = self._request('GET', endpoint=url, log_msg_action='get memberships',
                 auth_request=False)

        for interval in response['intervals']:
          if interval['available'] == True:
            now = datetime.datetime.now().astimezone()
            if now > datetime.datetime.strptime(interval['start_time'], "%Y-%m-%dT%H:%M:%S.%f%z") and now < datetime.datetime.strptime(interval['end_time'], "%Y-%m-%dT%H:%M:%S.%f%z"):
               if 'standby_duty' in interval['detailed_availability']:
                   interval['type'] = 'standby_duty'
               elif 'exception' in interval['detailed_availability']:
                   interval['type'] = 'exception'
               elif 'recurring' in interval['detailed_availability']:
                   interval['type'] = 'recurring'
               else:
                   interval['type'] = 'unknown'

               if interval['assigned_function_ids']:
                   for func in interval['assigned_function_ids']:
                       interval['assigned_function'] = self.get_standby_function(func)['name']

               return interval

        interval['available'] = False
        return interval


    def update(self):
        return self.get_availability()


    def _request(
        self,
        method: str,
        endpoint: str,
        log_msg_action: str,
        params: dict = None,
        body: dict = None,
        auth_request: bool = False,
    ) -> Optional[str]:
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
            f"Making request to {endpoint} endpoint to {log_msg_action}: "
            f"url: {url}, headers: {headers}, params: {params}, body: {body}"
        )

        try:
            response = requests.request(
                method, url, headers=headers, params=params, json=body, timeout=FSR_DEFAULT_TIMEOUT
            )

            try:
                log_msg = response.json()
            except:
                log_msg = response.text
            _LOGGER.debug(
                f"Request response: {response.status_code}: {log_msg}"
            )
            
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
                        "fireservicerota invalid credentials or refresh token invalid"
                    )
                else:
                    _LOGGER.error(
                        f"Error requesting authorization from fireservicerota: "
                        f"{response.status_code}: {json_payload}"
                    )
            elif response.status_code == 401:
                error = json_payload.get("error")
                if error == 'token_invalid':
                    raise InvalidTokenError(
                        "fireservicerota access token invalid; re-authentication required"
                    )
                elif error == 'token_revoked':
                    raise ExpiredTokenError(
                        "fireservicerota access token expired; token refresh required"
                    )
                else:
                    _LOGGER.error(
                        f"Error from fireservicerota while attempting to {log_msg_action}: "
                        f"{error}: {json_payload.get('status', {}).get('message', 'Unknown error')}"
                    )
            else:
                _LOGGER.error(
                    f"Error from fireservicerota while attempting to {log_msg_action}: "
                    f"{response.status_code}: {json_payload}"
                )
        except Timeout:
            _LOGGER.error(
                f"Connection to fireservicerrota timed out while attempting to {log_msg_action}. "
                f"Possible connectivity outage."
            )
        except (RequestException, json.decoder.JSONDecodeError):
            _LOGGER.error(
                f"Error connecting to fireservicerota while attempting to {log_msg_action}. "
                f"{response.status_code}: {json_payload}"
            )
        return None


class FireServiceRotaIncidents(Thread, websocket.WebSocketApp):
    def __init__(self, url,
                 on_incident=None,
                 on_error=None,):
        """
        :param url: websocket url
        :param on_incident: function that get's called on received incident
        :param on_error: function that get's called on error incident
        """
        self._url = url
        self.on_error = on_error

        Thread.__init__(self)
        websocket.WebSocketApp.__init__(self, self._url,
                                        on_open=self.on_open,
                                        on_error=self.on_error,
                                        on_message=self.on_message,
                                        on_close=self.on_close)

        self.connected = False
        self.on_incident = on_incident
        self._recent_incidents = deque(maxlen=30)

    def on_open(self):
        _LOGGER.debug('Websocket open')
        self.connected = True

    def on_close(self):
        _LOGGER.debug('Websocket closed')
        self.connected = False

    def on_message(self, message):
        _LOGGER.debug('Websocket data:' + message)
        try:
            message = json.loads(message)
            if "type" not in message:
                if "identifier" in message and json.loads(message["identifier"])["channel"] == "IncidentNotificationsChannel":
                    incident = message["message"]
                    """skip messages without message_to_speech_url and address info"""
                    if "address" in incident and "message_to_speech_url" in incident:
                        incident_id = incident["id"]
                        if incident_id not in self._recent_incidents:
                            self._recent_incidents.append(incident_id)
                            self.on_incident(incident)
                        else:
                            _LOGGER.debug("Skipping duplicate incident")
                else:
                    _LOGGER.debug(f"Malformed data received\n{message}")
            elif message["type"] == "welcome":
                _LOGGER.debug("Subscribing to the incidents channel")
                self.send(json.dumps({"command": "subscribe",
                           "identifier": json.dumps({ "channel": "IncidentNotificationsChannel" })}))
            elif message["type"] == "confirm_subscription":
                _LOGGER.debug("Succesfully subscribed to incidents channel")
            elif message["type"] == "ping":
                 pass
            else:
                _LOGGER.debug(f"Received unknown type: {message}")
        except Exception as e:
            logging.exception(e)

    def run_forever(self, sockopt=None, sslopt=None, ping_interval=0, ping_timeout=None):
        #    websocket.enableTrace(True)
        websocket.WebSocketApp.run_forever(self, sockopt=sockopt, sslopt=sslopt, ping_interval=ping_interval,
                                           ping_timeout=ping_timeout)

