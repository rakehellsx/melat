"""Host-local interprocess locks and JavaScript-safe monotonic numeric IDs."""
import fcntl
import os
import re
import time
from contextlib import contextmanager
from pathlib import Path


def state_dir():
    path = Path(os.environ.get('MELAT_STATE_DIR', '/tmp/melat-state'))
    path.mkdir(parents=True, exist_ok=True)
    return path


class LockBusyError(ValueError):
    pass


@contextmanager
def host_lock(name, timeout=0):
    if not re.fullmatch(r'[a-z0-9_-]+', name):
        raise ValueError('无效锁名称')
    with (state_dir() / f'{name}.lock').open('a+') as handle:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise LockBusyError('数据正在导入或修改，请稍后重试')
                time.sleep(.05)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def reserve_ids(count):
    with host_lock('identifiers', timeout=30):
        path = state_dir() / 'next-id'
        previous = int(path.read_text()) if path.exists() else 0
        first = max(previous + 1, time.time_ns() // 1000)
        last = first + count - 1
        if last >= 2 ** 53:
            raise RuntimeError('标识符超出前端整数范围')
        temporary = path.with_suffix('.new')
        with temporary.open('w') as stream:
            stream.write(str(last))
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
        return range(first, last + 1)


def next_id():
    return reserve_ids(1)[0]
