# Python: FireServiceRota / BrandweerRooster

Python 3 API wrapper for FireServiceRota and BrandweerRooster

## About

This package allows you to get notified about emergency incidents from FireServiceRota.co.uk and BrandweerRooster.nl.
Those are services used by firefighters.

See https://fireservicerota.co.uk and https://brandweerrooster.nl for more details.

NOTE: You need a subscription and login account to be able to use it.

## Installation

```bash
pip3 install pyfireservicerota
```

## Usage

```python
from pyfireservicerota import FireServiceRotaOAuth, FireServiceRotaOauthError, FireServiceRotaIncidentsListener
import logging
import sys
import json
import time
import threading

_LOGGER = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

oauth = FireServiceRotaOAuth(
        "https://www.brandweerrooster.nl/oauth/token",
        "",
        [CLIENT_ID],
        [CLIENT_SECRET],
    )

try:
    token_info = oauth.get_access_token()
except FireServiceRotaOauthError:
    token_info = None

if not token_info:
    _LOGGER.error("Failed to get access token")

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

    @property
    def data(self):
        """Return the current data stored in the provider."""
        return self._data

    def incidents_listener(self):
        """Spawn a new Listener and links it to self.on_incident."""

        _LOGGER.debug("Starting incidents listener")
        self.listener = FireServiceRotaIncidentsListener(url=wsurl, on_incident=self.on_incident)

        while True:
            try:
                self.listener.run_forever()
            except:
                pass


ws = FireService()

while True:
    time.sleep(1)
```

## TODO

Implement Oauth refresh token
