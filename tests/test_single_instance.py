import os
from core import single_instance

def test_second_acquire_fails_until_first_is_released(tmp_path):
    lock_path = str(tmp_path / "instance.lock")
    first = single_instance.acquire(lock_path)
    assert first is not None
    assert single_instance.acquire(lock_path) is None
    os.close(first)
    second = single_instance.acquire(lock_path)
    assert second is not None
    os.close(second)
