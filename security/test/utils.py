#!/usr/bin/env python3
'''General utilities for unit tests.'''

from unittest import mock


def auto_patch(monkeypatch: object, target: object, name: str) -> None:
    '''
    Creates a `mock` object with the spec of `target.name` and monkey
    patches `target.name` with this `mock`.

    Args:
        monkeypatch:    The pytest monkeypatch fixture.
        target:         The object to monkeypatch.
        name:           The attribute of the target to monkeypatch.
    '''
    spec = mock.create_autospec(getattr(target, name))
    monkeypatch.setattr(target, name, spec)
