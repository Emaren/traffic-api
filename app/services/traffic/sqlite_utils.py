from __future__ import annotations

import os
import sqlite3
from types import TracebackType
from typing import TypeVar

_Exc = TypeVar("_Exc", bound=BaseException)


class ClosingSQLiteConnection(sqlite3.Connection):
    """SQLite connection whose context-manager scope also owns its lifetime.

    sqlite3.Connection.__exit__ commits/rolls back but deliberately does not
    close. Traffic uses short-lived request/worker connections, so leaving
    closure to GC can retain WAL/read/write locks far beyond the logical scope.
    """

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def connect(
    database: str | bytes | "os.PathLike[str]" | "os.PathLike[bytes]",
    *,
    timeout: float = 5.0,
    uri: bool = False,
) -> ClosingSQLiteConnection:
    return sqlite3.connect(
        database,
        timeout=timeout,
        uri=uri,
        factory=ClosingSQLiteConnection,
    )
