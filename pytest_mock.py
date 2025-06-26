import pytest
from unittest.mock import patch

class MockerFixture:
    def __init__(self):
        self._patches = []

    def patch(self, *args, **kwargs):
        p = patch(*args, **kwargs)
        obj = p.start()
        self._patches.append(p)
        return obj

    def stopall(self):
        for p in reversed(self._patches):
            p.stop()
        self._patches.clear()

@pytest.fixture
def mocker():
    fixture = MockerFixture()
    try:
        yield fixture
    finally:
        fixture.stopall()
