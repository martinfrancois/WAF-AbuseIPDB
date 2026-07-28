from datetime import datetime, timedelta, timezone


def build_time_window(now: datetime, lookback_hours: float) -> tuple[str, str]:
    """Return a UTC Cloudflare query window in ISO 8601 format."""
    if lookback_hours <= 0:
        raise ValueError("lookback hours must be positive")

    now_utc = now.astimezone(timezone.utc)
    range_from = now_utc - timedelta(hours=lookback_hours)
    timestamp_format = "%Y-%m-%dT%H:%M:%SZ"
    return range_from.strftime(timestamp_format), now_utc.strftime(timestamp_format)
