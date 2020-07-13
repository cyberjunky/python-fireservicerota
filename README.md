# Python: FireServiceRota / BrandweerRooster

Basic Python 3 API wrapper for FireServiceRota and BrandweerRooster for use with Home Assistant

## About

This package allows you to get notified about emergency incidents from FireServiceRota.co.uk and BrandweerRooster.nl.
Those are services used by firefighters.

It currently provides the following limited functionality:

- Connect to the websocket to get incident details in near-realtime
- Get user availability (duty)
- Set user incident response status

See https://fireservicerota.co.uk and https://brandweerrooster.nl for more details.

NOTE: You need a subscription and login account to be able to use it.

## Installation

```bash
pip3 install pyfireservicerota
```

## Usage

# Initialise module using user credentials to get token_info
```python
from pyfireservicerota import FireServiceRota, FireServiceRotaIncidents, FireServiceRotaError, ExpiredTokenError, InvalidTokenError, InvalidAuthError
import logging
import sys
import json
import time
import threading

_LOGGER = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

token_info = {}

api = FireServiceRota(
      base_url="https://www.brandweerrooster.nl",
      username="your@email.address",
      password="yourpassword",
)

try:
    token_info = api.request_tokens()
except InvalidAuthError:
    token_info = None

if not token_info:
    _LOGGER.error("Failed to get access tokens")
```

NOTE: You don't need to store user credentials, at first authentication just the token_info dictionary is enough use api.refresh_tokens to refresh it.

# Initialise module with stored token_info
```python
from pyfireservicerota import FireServiceRota, FireServiceRotaIncidents, FireServiceRotaError, ExpiredTokenError, InvalidTokenError, InvalidAuthError
import logging
import sys
import json
import time
import threading

_LOGGER = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

token_info = {}

api = FireServiceRota(
      base_url = "https://www.brandweerrooster.nl",
      token_info = token_info
    )

# Get userid to fetch availability
try:
   print(api.get_userid())
except ExpiredTokenError:
   _LOGGER.debug("Tokens are expired, refreshing")
   try:
       token_info = api.refresh_tokens()
   except InvalidAuthError:
       _LOGGER.debug("Invalid refresh token, you need to re-login")
except InvalidTokenError:
    _LOGGER.debug("Tokens are invalid")
   try:
       token_info = api.refresh_tokens()
   except InvalidAuthError:
       _LOGGER.debug("Invalid refresh token, you need to re-login")

# Get user schedules
try:
   print(api.get_schedules())
except ExpiredTokenError:
   _LOGGER.debug("Tokens are expired, refreshing")
   try:
       token_info = api.refresh_tokens()
   except InvalidAuthError:
       _LOGGER.debug("Invalid refresh token, you need to re-login")
except InvalidTokenError:
    _LOGGER.debug("Tokens are invalid")
   try:
       token_info = api.refresh_tokens()
   except InvalidAuthError:
       _LOGGER.debug("Invalid refresh token, you need to re-login")

# Get user availability (duty)
try:
   print(api.get_availability())
except ExpiredTokenError:
   _LOGGER.debug("Tokens are expired, refreshing")
   try:
       token_info = api.refresh_tokens()
   except InvalidAuthError:
       _LOGGER.debug("Invalid refresh token, you need to re-login")
except InvalidTokenError:
    _LOGGER.debug("Tokens are invalid")
   try:
       token_info = api.refresh_tokens()
   except InvalidAuthError:
       _LOGGER.debug("Invalid refresh token, you need to re-login")

# Get incident response status for incident with id 123456

id = 123456

try:
   print(api.get_incident_response(id))
except ExpiredTokenError:
   _LOGGER.debug("Tokens are expired, refreshing")
   try:
       token_info = api.refresh_tokens()
   except InvalidAuthError:
       _LOGGER.debug("Invalid refresh token, you need to re-login")
except InvalidTokenError:
    _LOGGER.debug("Tokens are invalid")
   try:
       token_info = api.refresh_tokens()
   except InvalidAuthError:
       _LOGGER.debug("Invalid refresh token, you need to re-login")


# Set incident response to acknowlegded (False = 'rejected')
try:
   api.set_incident_response(id, True)
except ExpiredTokenError:
   _LOGGER.debug("Tokens are expired, refreshing")
   try:
       token_info = api.refresh_tokens()
   except InvalidAuthError:
       _LOGGER.debug("Invalid refresh token, you need to re-login")
except InvalidTokenError:
    _LOGGER.debug("Tokens are invalid")
   try:
       token_info = api.refresh_tokens()
   except InvalidAuthError:
       _LOGGER.debug("Invalid refresh token, you need to re-login")


# Connect to websocket channel for incidents
wsurl = f"wss://www.brandweerrooster.nl/cable?access_token={token_info['access_token']}"

class FireService():

    def __init__(self):

        self._data = None
        self.listener = None
        self.thread = threading.Thread(target=self.incidents_listener)
        self.thread.daemon = True
        self.thread.start()

    def on_incident(self, data):
        _LOGGER.debug("INCIDENT: %s", data)
        self._data = data

    def on_error(self, error):
        _LOGGER.debug("Websocket error: %s", error)

    def on_close(self):
        _LOGGER.debug("Websocket closed")
        return

    def incidents_listener(self):
        """Spawn a new Listener and links it to self.on_incident."""

        while True:
            _LOGGER.debug("Starting incidents listener")
            self.listener = FireServiceRotaIncidents(url=self.url, on_incident=self.on_incident, on_error=self.on_error, on_close=self.on_close)
            self.listener.run_forever()


ws = FireService()

while True:
    time.sleep(1)
```

