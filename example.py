#!/usr/bin/env python3
# Example script for pyfireservicerota - connects to www.brandweerrooster.nl
#
# Tests: token request, user availability, last incident fetch,
#        incident response get/set, and WebSocket incident notifications.
#
# Usage:
#   FSR_USERNAME=your@email.nl FSR_PASSWORD=secret python example.py
#   # or just:
#   python example.py  # prompts for credentials interactively

import logging
import os
import sys
import time
from getpass import getpass

from pyfireservicerota import (
    ExpiredTokenError,
    FireServiceRota,
    FireServiceRotaIncidents,
    InvalidAuthError,
    InvalidTokenError,
)

_LOGGER = logging.getLogger(__name__)

logging.basicConfig(level=logging.DEBUG)

token_info = {}
email = os.environ.get("FSR_USERNAME") or input("Login e-mail: ")
password = os.environ.get("FSR_PASSWORD") or getpass("Enter password: ")

if not email or not password:
    _LOGGER.error("Username and password are required")
    sys.exit(1)

api = FireServiceRota(
      base_url="www.brandweerrooster.nl",
      username=email,
      password=password,
)

_LOGGER.info("TEST: Requesting API tokens")
try:
    token_info = api.request_tokens()
except InvalidAuthError:
    token_info = None

api = FireServiceRota(
    base_url="www.brandweerrooster.nl",
    token_info=token_info,
)

_LOGGER.info("TEST: Fetching last incident")
incidents = api.get_incidents(limit=1)
if incidents:
    _LOGGER.info("Last incident: %s", incidents[0])
else:
    _LOGGER.info("No incidents returned (or endpoint not supported)")

_LOGGER.info("TEST: Getting user availability for Europe/Amsterdam")
try:
    _LOGGER.info(api.get_availability("Europe/Amsterdam"))
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

incident_id = incidents[0]["id"] if incidents else None

if not incident_id:
    _LOGGER.info("Skipping incident response tests, no incidents available")
else:
    _LOGGER.info("TEST: Getting incident response status for incident %s", incident_id)
    try:
        _LOGGER.info(api.get_incident_response(incident_id))
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

    _LOGGER.info("TEST: Setting incident response to acknowledged for incident %s", incident_id)
    try:
        api.set_incident_response(incident_id, True)
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

_LOGGER.info("TEST: Fetching pagers linked to this account")
pagers = api.get_pagers()
if pagers:
    _LOGGER.info("Pager fields available: %s", list(pagers[0].keys()))
    _LOGGER.info("Pager data: %s", pagers[0])
    pager_id = pagers[0]["id"]

    _LOGGER.info("TEST: Sending test message to pager %s", pager_id)
    result = api.send_pager_message(pager_id, "Test message from pyfireservicerota", confirmation=True)
    if result:
        _LOGGER.info("Message sent: id=%s acknowledgment_state=%s address=%s", result["id"], result["acknowledgment_state"], result.get("address"))

        _LOGGER.info("TEST: Polling delivery status for message %s", result["id"])
        status = api.get_pager_message_status(pager_id, result["id"])
        if status:
            _LOGGER.info("Delivery status: %s", status["acknowledgment_state"])
else:
    _LOGGER.info("No pagers linked to this account")

_LOGGER.info("TEST: Connecting to WebSocket for real-time incident notifications")
wsurl = f"wss://www.brandweerrooster.nl/cable?access_token={token_info['access_token']}"

class FireService():

    def __init__(self, url):

        self._data = None
        self.listener = None
        self.url = url
        self.incidents_listener()

    def on_incident(self, data):
        _LOGGER.info("INCIDENT: %s", data)
        self._data = data

    def incidents_listener(self):
        """Spawn a new Listener and links it to self.on_incident."""

        self.listener = FireServiceRotaIncidents(on_incident=self.on_incident)
        _LOGGER.debug("Starting incidents listener")
        self.listener.start(url=self.url)


ws = FireService(wsurl)

while True:
    time.sleep(1)
