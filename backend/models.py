from pydantic import BaseModel


class TrafficIn(BaseModel):
    timestamp: str
    src_ip: str
    dst_ip: str
    protocol: str = "TCP"
    src_port: int | None = None
    dst_port: int | None = None
    packet_size: int | None = None


class AlertUpdate(BaseModel):
    status: str | None = None  # NEW | INVESTIGATING | INVESTIGATED | FALSE_POSITIVE
    notes: str | None = None
