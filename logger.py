from datetime import datetime


def log_event(message: str, event_type: str = "INFO"):
    """
    Log security-related events with timestamp.

    Parameters:
    - message (str): Description of the event
    - event_type (str): INFO | ATTACK | ERROR

    Notes:
    - Logging failures must never interrupt the application.
    - Used for brute-force, dictionary, and hashing logs.
    """

    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        event_type = event_type.upper()

        log_entry = f"[{timestamp}] [{event_type}] {message}\n"

        with open("security_log.txt", "a") as log_file:
            log_file.write(log_entry)

    except Exception:
        # Fail silently to avoid interrupting the security tool
        pass
