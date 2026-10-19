"""One verified executable capability for a complete preparation exchange."""

from __future__ import annotations

from contextlib import contextmanager

from . import lifecycle


@contextmanager
def verified_preparation():
    """Pin verified bytes for all requests; never accept an executable from callers."""
    with lifecycle.session():

        def invoke(kind="preparation", **fields):
            return lifecycle.invoke(kind, **fields)

        yield invoke
