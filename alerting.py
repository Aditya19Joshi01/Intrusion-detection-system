import logging
from datetime import datetime

# Set up the logging configuration
logging.basicConfig(
    filename="alerts.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
)

# Function to log alerts
def log_alert(alert_type, message):
    alert_message = f"{alert_type}: {message}"
    logging.info(alert_message)
    print(f"[ALERT] {alert_message}")

# Optional: Function to send email notifications
def send_email_alert(alert_type, message):
    # Placeholder for email notification code
    pass

# Optional: Function to send SMS or other types of notifications
def send_sms_alert(alert_type, message):
    # Placeholder for SMS notification code
    pass
