"""End-to-end Windows pipeline: PCAP -> Docker/Zeek -> JSON -> Kafka.

PCAP files are mounted READ-ONLY into the Zeek container.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from producer import ZeekKafkaProducer


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

PCAP_INBOX = PROJECT_ROOT / "data" / "pcap" / "incoming"

PCAP_PROCESSED = PROJECT_ROOT / "data" / "pcap" / "processed"

ZEEK_LOG_ROOT = PROJECT_ROOT / "data" / "zeek_logs"

ZEEK_SCRIPT = PROJECT_ROOT / "zeek" / "local.zeek"

ZEEK_IMAGE = "zeek/zeek:lts"

SUPPORTED_EXTENSIONS = {
    ".pcap",
    ".pcapng",
    ".cap",
}


# ============================================================
# CHECK DOCKER
# ============================================================

def check_command_exists(command: str) -> None:
    """Check whether a required command is available."""

    result = subprocess.run(
        [command, "--version"],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"'{command}' is not available. "
            f"Make sure Docker Desktop is running."
        )


# ============================================================
# RUN ZEEK
# ============================================================

def run_zeek(
    pcap_path: Path,
    output_dir: Path,
) -> None:
    """Run Zeek inside Docker on the supplied PCAP."""

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    pcap_dir = pcap_path.parent.resolve()

    output_dir = output_dir.resolve()

    script_path = ZEEK_SCRIPT.resolve()

    command = [
        "docker",
        "run",
        "--rm",

        # PCAP is READ-ONLY.
        "--mount",
        (
            f"type=bind,"
            f"source={pcap_dir},"
            f"target=/pcap,"
            f"readonly"
        ),

        # Zeek logs are writable.
        "--mount",
        (
            f"type=bind,"
            f"source={output_dir},"
            f"target=/logs"
        ),

        # Zeek configuration is READ-ONLY.
        "--mount",
        (
            f"type=bind,"
            f"source={script_path.parent},"
            f"target=/config,"
            f"readonly"
        ),

        "--workdir",
        "/logs",

        ZEEK_IMAGE,

        "zeek",

        "-C",

        "-r",
        f"/pcap/{pcap_path.name}",

        "/config/local.zeek",
    ]

    print("\n[ZEEK] Running Zeek...")

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.stdout.strip():

        print(result.stdout.rstrip())

    if result.stderr.strip():

        print(
            result.stderr.rstrip(),
            file=sys.stderr,
        )

    if result.returncode != 0:

        raise RuntimeError(
            f"Zeek failed for {pcap_path.name} "
            f"with exit code {result.returncode}"
        )


# ============================================================
# CREATE OUTPUT DIRECTORY
# ============================================================

def make_output_dir(
    pcap_path: Path,
) -> Path:

    stamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    return (
        ZEEK_LOG_ROOT
        / f"{pcap_path.stem}_{stamp}"
    )


# ============================================================
# MOVE PCAP TO PROCESSED
# ============================================================

def move_to_processed(
    pcap_path: Path,
) -> None:
    """Move a completed PCAP to the processed directory."""

    PCAP_PROCESSED.mkdir(
        parents=True,
        exist_ok=True,
    )

    destination = (
        PCAP_PROCESSED
        / pcap_path.name
    )

    # If same filename already exists,
    # create a unique destination name.
    if destination.exists():

        suffix = datetime.now().strftime(
            "%Y%m%d_%H%M%S_%f"
        )

        destination = (
            PCAP_PROCESSED
            / (
                f"{pcap_path.stem}_"
                f"{suffix}"
                f"{pcap_path.suffix}"
            )
        )

    shutil.move(
        str(pcap_path),
        str(destination),
    )

    print(
        f"[FILE] Moved source PCAP to: "
        f"{destination}"
    )


# ============================================================
# PROCESS ONE PCAP
# ============================================================

def process_one(
    pcap_path: Path,
    producer: ZeekKafkaProducer,
) -> int:
    """Process one PCAP and send its events to Kafka."""

    if not pcap_path.exists():

        raise FileNotFoundError(
            pcap_path
        )

    if (
        pcap_path.suffix.lower()
        not in SUPPORTED_EXTENSIONS
    ):

        raise ValueError(
            f"Unsupported capture extension: "
            f"{pcap_path.suffix}"
        )

    output_dir = make_output_dir(
        pcap_path
    )

    print(
        f"\n=== Processing "
        f"{pcap_path.name} ==="
    )

    # --------------------------------------------------------
    # STEP 1: Run Zeek
    # --------------------------------------------------------

    run_zeek(
        pcap_path,
        output_dir,
    )

    # --------------------------------------------------------
    # STEP 2: Find Zeek logs
    # --------------------------------------------------------

    log_files = list(
        output_dir.glob("*.log")
    )

    if not log_files:

        raise RuntimeError(
            "Zeek completed, but no .log "
            "files were created."
        )

    print(
        f"[ZEEK] Generated "
        f"{len(log_files)} log files."
    )

    # --------------------------------------------------------
    # STEP 3: Send Zeek events to Kafka
    # --------------------------------------------------------

    total = producer.send_run_directory(
        output_dir,
        pcap_path.name,
    )

    print(
        f"[DONE] {pcap_path.name}: "
        f"{total} events sent to Kafka topic "
        f"'{producer.topic}'."
    )

    return total


# ============================================================
# WAIT UNTIL PCAP IS COMPLETELY COPIED
# ============================================================

def is_file_stable(
    pcap_path: Path,
    wait_time: float = 1.0,
) -> bool:
    """Check whether a PCAP has stopped growing."""

    try:

        size1 = pcap_path.stat().st_size

        time.sleep(wait_time)

        size2 = pcap_path.stat().st_size

        return size1 == size2

    except FileNotFoundError:

        return False


# ============================================================
# WATCH DIRECTORY
# ============================================================

def watch_directory(
    producer: ZeekKafkaProducer,
    interval: float,
) -> None:
    """Continuously watch the PCAP inbox."""

    PCAP_INBOX.mkdir(
        parents=True,
        exist_ok=True,
    )

    PCAP_PROCESSED.mkdir(
        parents=True,
        exist_ok=True,
    )

    print(
        f"[WATCH] Watching: "
        f"{PCAP_INBOX}"
    )

    print(
        "[WATCH] Put .pcap/.pcapng/.cap "
        "files there."
    )

    print(
        "[WATCH] Press Ctrl+C to stop."
    )

    # Files successfully ingested during
    # this watcher session.
    ingested_files: set[str] = set()

    while True:

        candidates = sorted(
            [
                p
                for p in PCAP_INBOX.iterdir()
                if (
                    p.is_file()
                    and p.suffix.lower()
                    in SUPPORTED_EXTENSIONS
                )
            ],
            key=lambda p: p.stat().st_mtime,
        )

        for pcap in candidates:

            # =================================================
            # IMPORTANT:
            # Never ingest the same filename twice
            # during one watcher session.
            # =================================================

            if pcap.name in ingested_files:

                # Try moving it again if the previous
                # move failed because the file was locked.
                try:

                    move_to_processed(
                        pcap
                    )

                except Exception as exc:

                    print(
                        f"[WAIT] {pcap.name} "
                        f"already ingested, but could "
                        f"not be moved yet: {exc}"
                    )

                continue

            try:

                print(
                    f"\n[NEW] Detected PCAP: "
                    f"{pcap.name}"
                )

                # =================================================
                # Make sure the PCAP is no longer being copied.
                # =================================================

                if not is_file_stable(pcap):

                    print(
                        f"[WAIT] {pcap.name} "
                        f"is still being copied."
                    )

                    continue

                # =================================================
                # PROCESS ONCE
                # =================================================

                process_one(
                    pcap,
                    producer,
                )

                # =================================================
                # VERY IMPORTANT:
                # Mark as ingested BEFORE moving.
                #
                # This prevents duplicate Kafka events if the
                # file move fails because another application
                # temporarily has the file open.
                # =================================================

                ingested_files.add(
                    pcap.name
                )

                # =================================================
                # MOVE TO PROCESSED
                # =================================================

                try:

                    move_to_processed(
                        pcap
                    )

                except Exception as move_error:

                    print(
                        f"[WAIT] {pcap.name} "
                        f"was successfully ingested "
                        f"but could not be moved yet: "
                        f"{move_error}"
                    )

            except Exception as exc:

                print(
                    f"[ERROR] {pcap.name}: "
                    f"{exc}",
                    file=sys.stderr,
                )

        time.sleep(
            interval
        )


# ============================================================
# ARGUMENTS
# ============================================================

def parse_args() -> argparse.Namespace:

    parser = argparse.ArgumentParser(
        description=(
            "PCAP -> Zeek -> Kafka "
            "ingestion pipeline"
        )
    )

    group = parser.add_mutually_exclusive_group(
        required=True
    )

    group.add_argument(
        "--pcap",
        type=Path,
        help=(
            "Process one "
            "PCAP/PCAPNG/CAP file"
        ),
    )

    group.add_argument(
        "--watch",
        action="store_true",
        help=(
            "Watch the incoming "
            "PCAP directory"
        ),
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help=(
            "Polling interval for "
            "--watch mode"
        ),
    )

    return parser.parse_args()


# ============================================================
# MAIN
# ============================================================

def main() -> int:

    args = parse_args()

    # --------------------------------------------------------
    # Check Docker
    # --------------------------------------------------------

    check_command_exists(
        "docker"
    )

    # --------------------------------------------------------
    # Create required directories
    # --------------------------------------------------------

    PCAP_INBOX.mkdir(
        parents=True,
        exist_ok=True,
    )

    PCAP_PROCESSED.mkdir(
        parents=True,
        exist_ok=True,
    )

    ZEEK_LOG_ROOT.mkdir(
        parents=True,
        exist_ok=True,
    )

    # --------------------------------------------------------
    # Create Kafka producer
    # --------------------------------------------------------

    producer = ZeekKafkaProducer()

    try:

        # ====================================================
        # ONE PCAP MODE
        # ====================================================

        if args.pcap:

            pcap_path = (
                args.pcap.resolve()
            )

            process_one(
                pcap_path,
                producer,
            )

        # ====================================================
        # WATCH MODE
        # ====================================================

        else:

            watch_directory(
                producer,
                args.interval,
            )

    except KeyboardInterrupt:

        print(
            "\n[STOP] Pipeline stopped by user."
        )

    finally:

        # Ensure queued Kafka messages are
        # delivered before shutting down.
        producer.producer.flush()

    return 0


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    raise SystemExit(
        main()
    )