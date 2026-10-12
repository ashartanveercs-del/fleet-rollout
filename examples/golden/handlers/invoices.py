"""Invoice helpers the support agent calls."""


def invoice_total(lines):
    """Sum line items given as (quantity, unit_price) pairs."""
    return round(sum(quantity * unit_price for quantity, unit_price in lines), 2)
