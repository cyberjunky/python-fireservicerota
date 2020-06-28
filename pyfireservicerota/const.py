"""Constants used."""
import logging

_LOGGER = logging.getLogger("pyfireservicerota")

FSR_DEFAULT_TIMEOUT = 20
FSR_ENDPOINT_TOKEN = "oauth/token"
FSR_ENDPOINT_USER = "users/current.json"
FSR_ENDPOINT_MEMBERSHIPS = "memberships/{}/combined_schedule?start_time={}&end_time={}"
FSR_ENDPOINT_SKILLS = "skills"
FSR_ENDPOINT_DUTY_STANDBY_FUNCTIONS = "standby_duty_functions"
FSR_ENDPOINT_DUTY_STANDBY_FUNCTION = "standby_duty_functions/{}"
