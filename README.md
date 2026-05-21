# Python: FireServiceRota / BrandweerRooster

Python 3 API wrapper for [FireServiceRota](https://www.fireservicerota.co.uk) and [BrandweerRooster](https://www.brandweerrooster.nl).

## About

This package provides access to emergency incident data from FireServiceRota and BrandweerRooster — services used by firefighters.

**Features:**
- Real-time incident notifications via WebSocket
- User availability (duty schedule)
- Incident response status (acknowledge / reject)
- Pager management: list pagers, send messages, poll delivery status

> A subscription and login account are required. See [fireservicerota.co.uk](https://fireservicerota.co.uk) or [brandweerrooster.nl](https://brandweerrooster.nl) for details.

## Installation

```bash
pip install pyfireservicerota
```

## Authentication

Authentication uses OAuth2 tokens. On first use, exchange your credentials for a `token_info` dict and store it. After that you only need the tokens — use `refresh_tokens()` to keep them valid without re-entering your password.

### First-time login

```python
from pyfireservicerota import FireServiceRota, InvalidAuthError

api = FireServiceRota(
    base_url="www.brandweerrooster.nl",
    username="your@email.address",
    password="yourpassword",
)

try:
    token_info = api.request_tokens()
except InvalidAuthError:
    print("Invalid credentials")
    token_info = None
```

### Subsequent use (stored tokens)

```python
from pyfireservicerota import FireServiceRota

api = FireServiceRota(
    base_url="www.brandweerrooster.nl",
    token_info=token_info,  # dict loaded from storage
)
```

### Refreshing tokens

Any API call can raise `ExpiredTokenError` or `InvalidTokenError` when the access token needs refreshing:

```python
from pyfireservicerota import ExpiredTokenError, InvalidTokenError, InvalidAuthError

try:
    result = api.get_availability("Europe/Amsterdam")
except (ExpiredTokenError, InvalidTokenError):
    try:
        token_info = api.refresh_tokens()
    except InvalidAuthError:
        print("Refresh token invalid, re-login required")
```

## Usage

### Availability

```python
availability = api.get_availability("Europe/Amsterdam")
print(availability)
# {"available": True, "type": "recurring", ...} or {"available": False}
```

### Incidents

```python
incident_id = 123456

# Get your response status for an incident
response = api.get_incident_response(incident_id)

# Acknowledge (True) or reject (False)
api.set_incident_response(incident_id, True)
```

### Real-time incident notifications (WebSocket)

```python
import time
from pyfireservicerota import FireServiceRotaIncidents

def on_incident(data):
    print(f"Incident received: {data}")

wsurl = f"wss://www.brandweerrooster.nl/cable?access_token={token_info['access_token']}"

listener = FireServiceRotaIncidents(on_incident=on_incident)
listener.start(url=wsurl)

while True:
    time.sleep(1)
```

### Pagers

```python
# List pagers linked to your account
pagers = api.get_pagers()
# [{"id": 6789, "user_id": 12345, "serial_number": "C202309.12345", "type": "Swissphone s.QUAD C35"}]

# Send a message
result = api.send_pager_message(6789, "Test alarm message")
if result:
    print(f"Sent: id={result['id']} status={result['status']}")

# With a delivery-status webhook
result = api.send_pager_message(
    6789,
    "Test alarm message",
    webhook_url="https://your.server/pager-callback",
)

# Poll delivery status
if result:
    status = api.get_pager_message_status(6789, result["id"])
    if status:
        print(status["status"])  # "delivered", "pending", or "failed"
```

## Exceptions

| Exception | When raised |
|---|---|
| `InvalidAuthError` | Wrong credentials or expired refresh token |
| `ExpiredTokenError` | Access token expired or revoked — call `refresh_tokens()` |
| `InvalidTokenError` | Access token invalid — call `refresh_tokens()` |
