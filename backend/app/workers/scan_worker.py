
import logging
import os
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path

from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.models.scan import Scan
from app.services.scans import (
    ScanServiceError,
    execute_scan,
    get_repository_workspace,
)

logger = logging.getLogger(__name__)

MAX_WORKERS = max(
    1,
    min(int(os.getenv("VULNGUARD_SCAN_WORKERS", "2")), 8),
)


class ScanWorkerManager:
    """In-process worker pool for asynchronous security scans."""

    def __init__(self) -> None:
        self._executor: ThreadPoolExecutor | None = None
        self._lock = threading.RLock()
        self._events: dict[int, threading.Event] = {}
        self._futures: dict[int, Future] = {}

    def start(self) -> None:
        with self._lock:
            if self._executor is None:
                self._executor = ThreadPoolExecutor(
                    max_workers=MAX_WORKERS,
                    thread_name_prefix="vulnguard-scan",
                )

    def submit(
        self,
        *,
        scan_id: int,
        owner_id: int,
        repository_id: int,
        scanner_names: list[str],
    ) -> None:
        self.start()

        with self._lock:
            if scan_id in self._futures:
                raise RuntimeError("This scan has already been submitted.")

            if self._executor is None:
                raise RuntimeError("The scan worker pool is unavailable.")

            cancel_event = threading.Event()
            self._events[scan_id] = cancel_event

            future = self._executor.submit(
                self._run_scan,
                scan_id,
                owner_id,
                repository_id,
                list(scanner_names),
                cancel_event,
            )
            self._futures[scan_id] = future

            future.add_done_callback(
                lambda completed, current_id=scan_id: self._on_done(
                    current_id, completed
                )
            )
    def request_cancel(self, scan_id: int) -> None:
        with self._lock:
            event = self._events.get(scan_id)

            if event is not None:
                event.set()
                logger.info("Cancellation requested for scan %s", scan_id)

    def _on_done(self, scan_id: int, future: Future) -> None:
        try:
            future.result()
        except Exception:
            logger.exception("Background scan %s crashed", scan_id)
        finally:
            with self._lock:
                self._events.pop(scan_id, None)
                self._futures.pop(scan_id, None)

    @staticmethod
    def _run_scan(
        scan_id: int,
        owner_id: int,
        repository_id: int,
        scanner_names: list[str],
        cancel_event: threading.Event,
    ) -> None:
        db: Session = SessionLocal()

        try:
            scan = db.get(Scan, scan_id)
            if scan is None:
                logger.warning("Scan %s no longer exists", scan_id)
                return

            # A cancellation may have been requested before the job started.
            db.refresh(scan)
            if scan.cancel_requested or cancel_event.is_set():
                scan.status = "cancelled"
                scan.finished_at = _utc_now()
                scan.current_scanner = None
                scan.progress_percent = min(scan.progress_percent, 99)
                db.commit()
                return

            if scan.status != "queued":
                logger.warning(
                    "Skipping scan %s with unexpected status %s",
                    scan_id,
                    scan.status,
                )
                return

            target: Path = get_repository_workspace(
                owner_id, repository_id
            )

            def is_cancelled() -> bool:
                if cancel_event.is_set():
                    return True

                # Read a cancellation request made by another API session.
                db.refresh(scan)
                return scan.cancel_requested

            def report_progress(name: str, percent: int) -> None:
                db.refresh(scan)

                if scan.cancel_requested or cancel_event.is_set():
                    return

                scan.current_scanner = name
                scan.progress_percent = max(
                    0, min(int(percent), 99)
                )
                db.commit()

            execute_scan(
                db,
                scan=scan,
                target=target,
                scanner_names=scanner_names,
                cancel_check=is_cancelled,
                progress_callback=report_progress,
            )

        except Exception:
            logger.exception("Scan worker failed for scan %s", scan_id)
            db.rollback()

            try:
                scan = db.get(Scan, scan_id)
                if scan is not None and scan.status in {"queued", "running"}:
                    scan.status = "failed"
                    scan.finished_at = _utc_now()
                    scan.current_scanner = None
                    scan.error_message = (
                        "The background scan could not be completed. "
                        "Check server logs for diagnostic details."
                    )
                    db.commit()
            except Exception:
                db.rollback()
                logger.exception(
                    "Could not persist failure state for scan %s", scan_id
                )
        finally:
            db.close()

    def shutdown(self) -> None:
        with self._lock:
            executor = self._executor
            self._executor = None

            for event in self._events.values():
                event.set()

        if executor is not None:
            # Don't block application shutdown indefinitely on a scanner.
            executor.shutdown(wait=False, cancel_futures=False)


def _utc_now():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)


scan_worker = ScanWorkerManager()
