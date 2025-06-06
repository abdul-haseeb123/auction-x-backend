from pydantic import BaseModel


class BidBase(BaseModel):
    bidder: str
    bid_amount: float
