"""Kafka producer for the PCAP -> Zeek -> Kafka pipeline."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from confluent_kafka import Producer

from parser import parse_zeek_line


KAFKA_BOOTSTRAP = "localhost:9092"
KAFKA_TOPIC = "zeek-events"


class ZeekKafkaProducer:
    """Wrap Zeek events in a common schema and publish them to Kafka."""

    def __init__(
        self,
        bootstrap: str = KAFKA_BOOTSTRAP,
        topic: str = KAFKA_TOPIC,
    ) -> None:

        self.topic = topic

        self.producer = Producer(
            {
                "bootstrap.servers": bootstrap,

                "client.id": "sih-zeek-ingestion",

                # Strong delivery guarantee.
                "acks": "all",

                # Prevent duplicate messages during retries.
                "enable.idempotence": True,

                # Compress Kafka messages.
                "compression.type": "snappy",

                # Small batching delay for throughput.
                "linger.ms": 5,

                # Retry transient broker failures.
                "retries": 10,
            }
        )

        self.sent = 0
        self.failed = 0

    # ========================================================
    # KAFKA DELIVERY CALLBACK
    # ========================================================

    def _delivery_report(
        self,
        err: Any,
        msg: Any,
    ) -> None:

        if err is not None:

            self.failed += 1

            print(
                f"[KAFKA ERROR] "
                f"topic={self.topic} "
                f"error={err}"
            )

            return

        print(
            f"[KAFKA OK] "
            f"topic={msg.topic()} "
            f"partition={msg.partition()} "
            f"offset={msg.offset()}"
        )

    # ========================================================
    # EVENT ID
    # ========================================================

    @staticmethod
    def _event_id(
        source_file: str,
        log_name: str,
        line_number: int,
        raw_line: str,
    ) -> str:
        """
        Create deterministic event ID.

        Same source + log + line + content
        always produces the same ID.
        """

        payload = (
            f"{source_file}|"
            f"{log_name}|"
            f"{line_number}|"
            f"{raw_line}"
        ).encode("utf-8")

        return hashlib.sha256(payload).hexdigest()

    # ========================================================
    # SEND ONE EVENT
    # ========================================================

    def send_event(
        self,
        event: dict[str, Any],
        *,
        source_file: str,
        log_name: str,
        line_number: int,
        raw_line: str,
    ) -> None:

        event_id = self._event_id(
            source_file,
            log_name,
            line_number,
            raw_line,
        )

        envelope = {
            "event_id": event_id,

            "event_type": log_name,

            "source": "pcap",

            "source_file": source_file,

            "ingested_at": (
                datetime.now(timezone.utc)
                .isoformat()
            ),

            "zeek": event,
        }

        # Use Zeek UID when available.
        # Otherwise use source IP.
        key = str(
            event.get("uid")
            or event.get("id.orig_h")
            or event.get("id.resp_h")
            or event_id
        )

        value = json.dumps(
            envelope,
            separators=(",", ":"),
            ensure_ascii=False,
        )

        # ----------------------------------------------------
        # Kafka produce is asynchronous.
        # ----------------------------------------------------

        while True:

            try:

                self.producer.produce(
                    self.topic,

                    key=key.encode("utf-8"),

                    value=value.encode("utf-8"),

                    callback=self._delivery_report,
                )

                break

            except BufferError:

                # Producer queue is full.
                # Give Kafka time to process queued messages.
                self.producer.poll(0.5)

        self.producer.poll(0)

        self.sent += 1

    # ========================================================
    # SEND ONE ZEEK LOG FILE
    # ========================================================

    def send_log_file(
        self,
        log_path: Path,
        source_file: str,
    ) -> int:

        count = 0

        log_name = log_path.stem

        try:

            with log_path.open(
                "r",
                encoding="utf-8",
            ) as handle:

                for line_number, raw_line in enumerate(
                    handle,
                    start=1,
                ):

                    event = parse_zeek_line(
                        raw_line
                    )

                    if event is None:
                        continue

                    self.send_event(
                        event,

                        source_file=source_file,

                        log_name=log_name,

                        line_number=line_number,

                        raw_line=raw_line.rstrip("\n"),
                    )

                    count += 1

        except OSError as exc:

            print(
                f"[ERROR] Could not read "
                f"{log_path}: {exc}"
            )

            return 0

        return count

    # ========================================================
    # SEND COMPLETE ZEEK RUN DIRECTORY
    # ========================================================

    def send_run_directory(
        self,
        run_dir: Path,
        source_file: str,
    ) -> int:

        total = 0

        log_files = sorted(
            run_dir.glob("*.log")
        )

        for log_path in log_files:

            count = self.send_log_file(
                log_path,
                source_file,
            )

            print(
                f"[INGEST] "
                f"{log_path.name}: "
                f"{count} JSON events"
            )

            total += count

        # Wait until all queued messages
        # have been delivered.
        remaining = self.producer.flush()

        if remaining > 0:

            print(
                f"[KAFKA WARNING] "
                f"{remaining} messages "
                f"were not delivered."
            )

        print(
            f"[SUMMARY] "
            f"sent={self.sent} "
            f"failed={self.failed}"
        )

        return total