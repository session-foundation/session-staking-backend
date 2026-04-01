from attr import dataclass


@dataclass
class PriceDB:
    token: str
    price: float
    market_cap: float
    updated_at: int
    fetched_at: int
