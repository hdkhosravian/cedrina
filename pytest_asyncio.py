import asyncio
import inspect
import pytest

fixture = pytest.fixture

@pytest.fixture
def event_loop():
    loop = asyncio.new_event_loop()
    try:
        yield loop
    finally:
        loop.close()


def pytest_pyfunc_call(pyfuncitem):
    test_func = pyfuncitem.obj
    if inspect.iscoroutinefunction(test_func):
        loop = pyfuncitem.funcargs.get('event_loop')
        if loop is None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(test_func(**pyfuncitem.funcargs))
            finally:
                loop.close()
        else:
            loop.run_until_complete(test_func(**pyfuncitem.funcargs))
        return True

