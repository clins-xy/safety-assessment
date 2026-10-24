import re
from datetime import datetime, timedelta, timezone


TIME_FORMAT = "%Y/%m/%d/%H.%M"
BEIJING_TIME = timezone(timedelta(hours=8), name="Asia/Shanghai")
COMPACT_TIME = re.compile(r"^\d{4}/\d{2}/\d{2}/\d{2}\.\d{2}$")


def format_timestamp(value: datetime | str) -> str:
    if isinstance(value, str):
        if COMPACT_TIME.fullmatch(value):
            datetime.strptime(value, TIME_FORMAT)
            return value
        value = datetime.fromisoformat(value)
    # Legacy naive timestamps follow the previous application's UTC convention.
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(BEIJING_TIME).strftime(TIME_FORMAT)


def now() -> str:
    return format_timestamp(datetime.now(timezone.utc))
