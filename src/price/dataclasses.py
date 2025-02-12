from attr import dataclass


@dataclass
class PriceDB:
    token: str
    currency: str
    price: float
    market_cap: float
    updated_at: int
