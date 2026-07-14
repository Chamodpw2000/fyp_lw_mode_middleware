#!/usr/bin/env python3
"""
VANET Attack Detector Middleware
Watches /tmp/ for vanet_attack_ready_N sentinel files
Reads vanet_metrics_N.json and invokes attack detection chaincode
"""

import os
import csv
import json
import logging
import time
import sys
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import WATCH_DIR, LOG_FILE
from fabric_client import detect_attacks

# Attack-detection pipeline reads from a dedicated subfolder, separate
# from WATCH_DIR (which still serves the vanet_ready_N middleware).
ATTACK_WATCH_DIR = "/tmp/ai_agent"


# Permanent CSV containing attackers detected across all cycles
DETECTED_ATTACKERS_CSV = os.path.join(
    ATTACK_WATCH_DIR,
    "detected_attackers.csv"
)

# ─── Logging Setup ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


# ─── Attack Type Labels ───────────────────────────────────────────────────────
ATTACK_LABELS = {
    "Interleaved_Jamming_Attack": "🔴 INTERLEAVED GRAY HOLE ATTACK",
    "Split_Path_Attack":          "🟠 SPLIT PATH ATTACK",
    "Flow_Stretching_Attack":     "🟡 FLOW STRETCHING ATTACK",
}

# ─── CSV → Chaincode Input Transform ──────────────────────────────────────────

def transform_csv_row(row: dict) -> dict:
    """
    Maps one row of ff_node_anomaly_scores_N.csv into the node-dict shape
    expected by the DetectAttacks chaincode.

    CSV column          → chaincode field
    ───────────────────────────────────────────────
    node_id              → node_id
    flow_id               → flow_id
    sum_abs_ff_deviation_normalized → flow_fraction
    node_pdr              → pdrn   (divided by 100)
    inbound_ratio         → inbound_ratio
    """
    return {
        "node_id": int(row["node_id"]),
        "flow_id": int(row["flow_id"]),
        "flow_fraction": float(row["sum_abs_ff_deviation_normalized"]),
        "pdrn": float(row["node_pdr"]) / 100.0,
        "inbound_ratio": float(row["inbound_ratio"])
    }


def load_metrics_from_csv(csv_file: str) -> dict:
    """
    Reads ff_node_anomaly_scores_N.csv and returns the chaincode input shape:
        { "sim_time": <float>, "nodes": [ {...}, {...}, ... ] }

    sim_time is taken from the sim_time column of the first row — all rows
    in a given cycle's CSV share the same sim_time, since one file = one cycle.
    """
    nodes = []
    sim_time = 0.0
    first_row = True

    with open(csv_file, "r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if first_row:
                sim_time = float(row["sim_time_s"])
                first_row = False
            nodes.append(transform_csv_row(row))

    return {"sim_time": sim_time, "nodes": nodes}
# ─── Core Processing Pipeline ─────────────────────────────────────────────────

def save_detected_attackers(
    cycle_id: int,
    sim_time: float,
    detections: list
) -> None:
    """
    Appends detected attackers to detected_attackers.csv.

    Each detected attacker is stored as a separate row.
    The CSV file is created automatically if it does not exist.
    """

    if not detections:
        return

    os.makedirs(ATTACK_WATCH_DIR, exist_ok=True)

    fieldnames = [
        "cycle_id",
        "sim_time_s",
        "detected_at",
        "node_id",
        "flow_id",
        "attack_type",
        "flow_fraction",
        "pdrn",
        "inbound_ratio"
    ]

    file_exists = os.path.exists(DETECTED_ATTACKERS_CSV)
    file_is_empty = file_exists and os.path.getsize(DETECTED_ATTACKERS_CSV) == 0

    with open(
        DETECTED_ATTACKERS_CSV,
        "a",
        newline="",
        encoding="utf-8"
    ) as csv_file:

        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

        # Write the header only when creating a new or empty file
        if not file_exists or file_is_empty:
            writer.writeheader()

        for detection in detections:
            writer.writerow({
                "cycle_id": cycle_id,
                "sim_time_s": sim_time,
                "detected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "node_id": detection.get("node_id", ""),
                "flow_id": detection.get("flow_id", ""),
                "attack_type": detection.get("attack_type", ""),
                "flow_fraction": detection.get("flow_fraction", ""),
                "pdrn": detection.get("pdrn", ""),
                "inbound_ratio": detection.get("inbound_ratio", "")
            })

    logger.info(
        f"Cycle {cycle_id}: saved {len(detections)} detection(s) "
        f"to {DETECTED_ATTACKERS_CSV}"
    )

def save_cycle_detection_summary(
    cycle_id: int,
    nodes: list,
    detections: list
) -> None:
    """
    Creates one detection summary CSV for a single cycle.

    Output columns:
        node_id, detected, attack_type

    detected:
        1 = node was detected as an attacker
        0 = node was not detected as an attacker

    A node with no detected attack will have an empty attack_type.
    """

    summary_file = os.path.join(
        ATTACK_WATCH_DIR,
        f"detection_summary_cycle_{cycle_id}.csv"
    )

    # Store every unique node ID sent to DetectAttacks.
    # The original input order is preserved.
    node_ids = []
    seen_node_ids = set()

    for node in nodes:
        node_id = int(node["node_id"])

        if node_id not in seen_node_ids:
            seen_node_ids.add(node_id)
            node_ids.append(node_id)

    # Build a mapping such as:
    # {
    #     3: ["Split_Path_Attack"],
    #     10: ["Interleaved_Jamming_Attack"]
    # }
    detection_map = {}

    for detection in detections or []:
        node_id = int(detection["node_id"])
        attack_type = str(
            detection.get("attack_type", "Unknown_Attack")
        )

        detection_map.setdefault(node_id, [])

        # Avoid writing the same attack type more than once
        # for the same node.
        if attack_type not in detection_map[node_id]:
            detection_map[node_id].append(attack_type)

    # "w" creates a new file or replaces the old file
    # if the same cycle is processed again.
    with open(
        summary_file,
        "w",
        newline="",
        encoding="utf-8"
    ) as csv_file:

        fieldnames = [
            "node_id",
            "detected",
            "attack_type"
        ]

        writer = csv.DictWriter(
            csv_file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for node_id in node_ids:
            attack_types = detection_map.get(node_id, [])

            writer.writerow({
                "node_id": node_id,
                "detected": 1 if attack_types else 0,
                "attack_type": ";".join(attack_types),
            })

    logger.info(
        f"Cycle {cycle_id}: wrote detection summary for "
        f"{len(node_ids)} nodes to {summary_file}"
    )



def process_metrics(cycle_id: int, metrics_file: str, sentinel_file: str):
    """
    Full pipeline for attack detection in one cycle:
    1. Read node metrics from CSV file
    2. Invoke DetectAttacks chaincode
    3. Log detections
    4. Cleanup temp files
    """

    logger.info(f"{'='*50}")
    logger.info(f"Attack detection cycle {cycle_id}")

    try:
        # ── Step 1: Read and transform node metrics ───────────────────────────
        if not os.path.exists(metrics_file):
            logger.error(f"Metrics file not found: {metrics_file}")
            return

        data = load_metrics_from_csv(metrics_file)

        nodes = data.get("nodes", [])
        sim_time = data.get("sim_time", 0.0)

        if not nodes:
            logger.warning(f"Cycle {cycle_id}: no node metrics found")
            return

        logger.info(f"Cycle {cycle_id}: read metrics for {len(nodes)} nodes")

        # ── Step 2: Invoke DetectAttacks chaincode ────────────────────────────
        logger.info(f"Cycle {cycle_id}: invoking attack detection...")
        detections = detect_attacks(cycle_id, sim_time, nodes)
        # Create one node-level detection summary CSV for this cycle.
        #
        # This is outside the "if not detections" condition so that the
        # summary file is created even when no attacks are detected.
        save_cycle_detection_summary(
            cycle_id=cycle_id,
            nodes=nodes,
            detections=detections
        )
 
        # ── Step 3: Log and save results ─────────────────────────────────────
        if not detections:
            logger.info(
                f"Cycle {cycle_id}: ✓ No attacks detected — all nodes clean"
            )
        else:
            logger.warning(
                f"Cycle {cycle_id}: ⚠ {len(detections)} attack(s) detected!"
            )

            for d in detections:
                attack_type = d.get("attack_type", "Unknown_Attack")
                label = ATTACK_LABELS.get(attack_type, attack_type)

                logger.warning(
                    f"  {label} | "
                    f"Node: {d.get('node_id', 'N/A')} | "
                    f"Flow: {d.get('flow_id', 'N/A')} | "
                    f"FF: {float(d.get('flow_fraction', 0.0)):.3f} | "
                    f"PDRN: {float(d.get('pdrn', 0.0)):.3f}"
                )

            # Append all detections from this cycle to the permanent CSV
            save_detected_attackers(
                cycle_id=cycle_id,
                sim_time=sim_time,
                detections=detections
            )

    except Exception as e:
        logger.error(f"Cycle {cycle_id}: detection error: {e}")

    finally:
        # ── Step 4: Cleanup sentinel only ────────────────────────────────────
        # Keep ff_node_anomaly_scores_N.csv for later analysis.
        try:
            if os.path.exists(sentinel_file):
                os.remove(sentinel_file)
                logger.debug(f"Cleaned up sentinel: {sentinel_file}")
        except Exception as e:
            logger.warning(
                f"Could not remove sentinel {sentinel_file}: {e}"
            )

        logger.info(
            f"Cycle {cycle_id}: retained metrics CSV: {metrics_file}"
        )


# ─── File System Watcher ──────────────────────────────────────────────────────

class MetricsEventHandler(FileSystemEventHandler):
    """
    Watches /tmp/ for vanet_attack_ready_N sentinel files.

    fix.cc creates:
        /tmp/vanet_metrics_N.json      ← node metrics data
        /tmp/vanet_attack_ready_N      ← sentinel (triggers this middleware)

    Separate from vanet_ready_N which triggers Middleware 1.
    """

    def on_created(self, event):
        if event.is_directory:
            return

        filename = os.path.basename(event.src_path)

        # Only react to attack detection sentinel files
        if not filename.startswith("vanet_attack_ready_"):
            return

        # Extract cycle number
        try:
            cycle_id = int(filename.replace("vanet_attack_ready_", ""))
        except ValueError:
            logger.warning(f"Could not parse cycle id from: {filename}")
            return

        metrics_file  = os.path.join(ATTACK_WATCH_DIR, f"ff_node_anomaly_scores_{cycle_id}.csv")
        sentinel_file = event.src_path

        logger.info(f"Attack sentinel detected: {filename} → cycle {cycle_id}")

        # Small delay to ensure metrics file is fully written
        time.sleep(0.1)

        process_metrics(cycle_id, metrics_file, sentinel_file)


# ─── Entry Point ──────────────────────────────────────────────────────────────

def main():
    logger.info("VANET Attack Detector starting...")
    # /tmp may be cleared after a reboot.
    # Create the directory before glob() and Watchdog access it.
    os.makedirs(ATTACK_WATCH_DIR, exist_ok=True)
    logger.info(f"Watching directory: {ATTACK_WATCH_DIR}")
    logger.info(f"Log file: {LOG_FILE}")
    logger.info(f"Sentinel pattern: vanet_attack_ready_N")

    # Process any missed cycles at startup

    import glob
    missed = sorted(glob.glob(os.path.join(ATTACK_WATCH_DIR, "vanet_attack_ready_*")))
    for sentinel in missed:
        filename = os.path.basename(sentinel)
        try:
            cycle_id = int(filename.replace("vanet_attack_ready_", ""))
            metrics_file = os.path.join(ATTACK_WATCH_DIR, f"ff_node_anomaly_scores_{cycle_id}.csv")
            logger.info(f"Found missed cycle at startup: {cycle_id}")
            process_metrics(cycle_id, metrics_file, sentinel)
        except ValueError:
            pass
    # Start file watcher
    event_handler = MetricsEventHandler()
    observer = Observer()
    observer.schedule(event_handler, ATTACK_WATCH_DIR, recursive=False)
    observer.start()

    logger.info("Attack detector ready — waiting for metrics from fix.cc...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Attack detector stopping...")
        observer.stop()

    observer.join()
    logger.info("Attack detector stopped")


if __name__ == "__main__":
    main()
