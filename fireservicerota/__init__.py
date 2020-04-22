# -*- coding: utf-8 -*-
"""Python 3 API wrapper for FireServiceRota and BrandweerRooster."""
import json
import time
import logging
from collections import deque
import oauthlib.oauth2
import websocket
import requests
from threading import Thread

_LOGGER = logging.getLogger(__name__)

class FireServiceRotaIncidentsListener(Thread, websocket.WebSocketApp):
    def __init__(self, url,
                 on_incident=None,
                 on_error=None,):
        """
        :param url: websocket url
        :param on_incident: function that get's called on received incident
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
        self.last_update = time.time()
        self.on_incident = on_incident
        self._recent_incidents = deque(maxlen=30)

    def on_open(self):
        _LOGGER.debug('Websocket open')
        self.connected = True
        self.last_update = time.time()

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
                _LOGGER.debug("Got ping")
                self.send(json.dumps({"type": "pong","message": message["message"]}))
            else:
                _LOGGER.debug(f"Received unknown type: {message}")
        except Exception as e:
            logging.exception(e)

    def run_forever(self, sockopt=None, sslopt=None, ping_interval=0, ping_timeout=None):
        websocket.setdefaulttimeout=1
        websocket.enableTrace(True)
        websocket.WebSocketApp.run_forever(self, sockopt=sockopt, sslopt=sslopt, ping_interval=ping_interval,
                                           ping_timeout=ping_timeout)


class FireServiceRotaOAuth():
      """Implements Authorization Code Flow for FireServiceRota's OAuth implementation."""
      def __init__(self, authentication_url=None, client_id=None, username=None, password=None):
         """Init module"""
         self._authentication_url = authentication_url
         self._client_id = client_id
         self._username = username
         self._password = password


      def get_access_token(self):
         """Get access token."""
         try:
            oauth_client = oauthlib.oauth2.LegacyApplicationClient(self._client_id)
            request_body = oauth_client.prepare_request_body(
                     username=self._username, password=self._password)
            request_response = requests.post(url=self._authentication_url,
                     params=str.encode(request_body))

            request_response.raise_for_status()

         except requests.exceptions.HTTPError as errh:
            raise FireServiceRotaOauthError(errh.response.text)
         except requests.exceptions.ConnectionError as errc:
            raise FireServiceRotaOauthError(errc.response.text)
         except requests.exceptions.Timeout as errt:
            raise FireServiceRotaOauthError(errt.response.text)
         except requests.exceptions.RequestException as err:
            raise FireServiceRotaOauthError(err.response.text)

         parsed_response = oauth_client.parse_request_body_response(
                     request_response.content)

         return parsed_response


      def refresh_access_token(self, token_info):
         """Refresh access token if expired."""
         if token_info is None:
               return token_info
         if not self.is_token_expired(token_info):
               return token_info

         try:         
            oauth_client = oauthlib.oauth2.LegacyApplicationClient(self._client_id)
            request_body = request_body = oauth_client.prepare_request_body(
                     username=self._username, password=self._password)
            request_body = oauth_client.prepare_refresh_body(
                     request_body, refresh_token=token_info['refresh_token'])
            request_response = requests.post(url=self._authentication_url,
                     params=str.encode(request_body))

            request_response.raise_for_status()

         except requests.exceptions.HTTPError as errh:
            raise FireServiceRotaOauthError(errh.response.text)
         except requests.exceptions.ConnectionError as errc:
            raise FireServiceRotaOauthError(errc.response.text)
         except requests.exceptions.Timeout as errt:
            raise FireServiceRotaOauthError(errt.response.text)
         except requests.exceptions.RequestException as err:
            raise FireServiceRotaOauthError(err.response.text)

         parsed_response = oauth_client.parse_request_body_response(
                     request_response.content)

         return parsed_response


      def is_token_expired(self, token_info):
         """Check if auth token is expired."""
         return token_info['expires_at'] - int(time.time()) < 60*60


class FireServiceRotaOauthError(Exception):
    """Raised when oauth returns wrong result."""

    def __init__(self, status):
        """Initialize."""
        super(FireServiceRotaOauthError, self).__init__(status)
        self.status = status

