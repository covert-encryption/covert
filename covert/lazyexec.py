import collections
import itertools
import time


# Adopted from Python standard library PR https://github.com/python/cpython/pull/18566
def map(self, fn, *iterables, timeout=None, chunksize=1, prefetch=None):
  if timeout is not None:
    end_time = timeout + time.monotonic()
  if prefetch is None:
    prefetch = self._max_workers
  if prefetch < 0:
    raise ValueError("prefetch count may not be negative")

  argsiter = zip(*iterables)
  initialargs = itertools.islice(argsiter, self._max_workers + prefetch)

  fs = collections.deque(self.submit(fn, *args) for args in initialargs)

  # Yield must be hidden in closure so that the futures are submitted
  # before the first iterator value is required.
  def result_iterator():
    nonlocal argsiter
    try:
      while fs:
        if timeout is None:
          res = [fs[0].result()]
        else:
          res = [fs[0].result(end_time - time.monotonic())]

        # Got a result, future needn't be cancelled
        del fs[0]

        # Dispatch next task before yielding to keep
        # pipeline full
        if argsiter:
          try:
            args = next(argsiter)
          except StopIteration:
            argsiter = None
          else:
            fs.append(self.submit(fn, *args))
        yield res.pop()
    finally:
      for future in fs:
        future.cancel()

  return result_iterator()
