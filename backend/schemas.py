from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator

Policy = Literal["top_0.5pct", "top_1pct", "top_2pct", "top_5pct"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class Event(StrictModel):
    event_id: int = Field(ge=0, le=2**53-1, strict=True)
    timestamp: datetime
    entity_id: str = Field(min_length=1, max_length=100)
    entity_type: Literal["user", "service_account", "edge_device"]
    role: str = Field(min_length=1, max_length=100)
    source_ip: str = Field(max_length=45)
    geo_city: str = Field(min_length=1, max_length=100)
    geo_lat: float = Field(ge=-90, le=90)
    geo_lon: float = Field(ge=-180, le=180)
    resource_accessed: str = Field(min_length=1, max_length=200)
    auth_result: Literal["SUCCESS", "FAILURE"]
    bytes_out: float = Field(ge=0, le=10**12)
    device_os: str = Field(min_length=1, max_length=100)
    device_mac: str = Field(pattern=r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
    protocol: str = Field(min_length=1, max_length=30)
    session_id: str = Field(min_length=1, max_length=150)

    @field_validator("timestamp")
    @classmethod
    def utc_timestamp(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a UTC offset")
        if not 2000 <= value.year <= 2100:
            raise ValueError("timestamp year must be between 2000 and 2100")
        return value.astimezone(timezone.utc)

    @field_validator("source_ip")
    @classmethod
    def valid_ip(cls, value):
        return str(ip_address(value))

    @field_serializer("timestamp")
    def serialize_timestamp(self, value):
        return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class Batch(StrictModel):
    events: list[Event] = Field(min_length=1, max_length=250)


class NewSession(StrictModel):
    policy: Policy = "top_2pct"


class Feedback(StrictModel):
    request_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{12,80}$")
    event_id: int = Field(ge=0, strict=True)
    disposition: Literal["confirmed_attack", "benign", "needs_investigation"]
    note: str = Field(default="", max_length=2000)
