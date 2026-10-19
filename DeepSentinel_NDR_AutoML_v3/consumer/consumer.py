"""Debug consumer: prints events arriving on zeek-events."""

from __future__ import annotations

import argparse
import json

from confluent_kafka import Consumer


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--topic", default="zeek-events")
    parser.add_argument("--group", default="zeek-debug-consumer")
    args = parser.parse_args()

    consumer = Consumer(
        {
            "bootstrap.servers": "localhost:9092",
            "group.id": args.group,
            "auto.offset.reset": "earliest",
            "enable.auto.commit": True,
        }
    )

    consumer.subscribe([args.topic])
    print(f"[CONSUMER] Listening on topic '{args.topic}'. Press Ctrl+C to stop.")

    try:
        while True:
            message = consumer.poll(1.0)
            if message is None:
                continue

            if message.error():
                print(f"[KAFKA ERROR] {message.error()}")
                continue

            raw = message.value()
            if raw is None:
                continue

            try:
                event = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                print("[WARN] Received non-JSON message; skipping.")
                continue

            print(json.dumps(event, indent=2, ensure_ascii=False))
            print("-" * 80)

    except KeyboardInterrupt:
        print("\n[CONSUMER] Stopping.")
    finally:
        consumer.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
