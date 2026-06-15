#!/usr/bin/env python3
"""
VANET Attack Detector Middleware
Watches /tmp/ for vanet_attack_ready_N sentinel files
Reads vanet_metrics_N.json and invokes attack detection chaincode
"""

import os
import json
import logging
import time
import sys
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import WATCH_DIR, LOG_FILE
from fabric_client import detect_attacks

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
    "Interleaved_Jamming_Attack": "🔴 INTERLEAVED JAMMING ATTACK",
    "Split_Path_Attack":          "🟠 SPLIT PATH ATTACK",
    "Flow_Stretching_Attack":     "🟡 FLOW STRETCHING ATTACK",
}


# ─── Core Processing Pipeline ─────────────────────────────────────────────────

def process_metrics(cycle_id: int, metrics_file: str, sentinel_file: str):
    """
    Full pipeline for attack detection in one cycle:
    1. Read node metrics from JSON file
    2. Invoke DetectAttacks chaincode
    3. Log detections
    4. Cleanup temp files
    """

    logger.info(f"{'='*50}")
    logger.info(f"Attack detection cycle {cycle_id}")

    try:
        # ── Step 1: Read node metrics ─────────────────────────────────────────
        if not os.path.exists(metrics_file):
            logger.error(f"Metrics file not found: {metrics_file}")
            return

        with open(metrics_file, "r") as f:
            data = json.load(f)

        nodes = data.get("nodes", [])
        sim_time = data.get("sim_time", 0.0)

        if not nodes:
            logger.warning(f"Cycle {cycle_id}: no node metrics found")
            return

        logger.info(f"Cycle {cycle_id}: read metrics for {len(nodes)} nodes")

        # ── Step 2: Invoke DetectAttacks chaincode ────────────────────────────
        logger.info(f"Cycle {cycle_id}: invoking attack detection...")
        detections = detect_attacks(cycle_id, sim_time, nodes)

        # ── Step 3: Log results ───────────────────────────────────────────────
        if not detections:
            logger.info(f"Cycle {cycle_id}: ✓ No attacks detected — all nodes clean")
        else:
            logger.warning(f"Cycle {cycle_id}: ⚠ {len(detections)} attack(s) detected!")
            for d in detections:
                label = ATTACK_LABELS.get(d['attack_type'], d['attack_type'])
                logger.warning(
                    f"  {label} | "
                    f"Node: {d['node_id']} | "
                    f"Flow: {d['flow_id']} | "
                    f"FF: {d['flow_fraction']:.3f} | "
                    f"PDRN: {d['pdrn']:.3f} | "
                    f"Variance: {d['variance']:.4f}"
                )

    except Exception as e:
        logger.error(f"Cycle {cycle_id}: detection error: {e}")

    finally:
        # ── Step 4: Cleanup temp files ────────────────────────────────────────
        for f in [metrics_file, sentinel_file]:
            try:
                if os.path.exists(f):
                    os.remove(f)
                    logger.debug(f"Cleaned up: {f}")
            except Exception as e:
                logger.warning(f"Could not remove {f}: {e}")


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

        metrics_file  = os.path.join(WATCH_DIR, f"vanet_metrics_{cycle_id}.json")
        sentinel_file = event.src_path

        logger.info(f"Attack sentinel detected: {filename} → cycle {cycle_id}")

        # Small delay to ensure metrics file is fully written
        time.sleep(0.1)

        process_metrics(cycle_id, metrics_file, sentinel_file)


# ─── Entry Point ──────────────────────────────────────────────────────────────

def main():
    logger.info("VANET Attack Detector starting...")
    logger.info(f"Watching directory: {WATCH_DIR}")
    logger.info(f"Log file: {LOG_FILE}")
    logger.info(f"Sentinel pattern: vanet_attack_ready_N")

    # Process any missed cycles at startup
    import glob
    missed = sorted(glob.glob(os.path.join(WATCH_DIR, "vanet_attack_ready_*")))
    for sentinel in missed:
        filename = os.path.basename(sentinel)
        try:
            cycle_id = int(filename.replace("vanet_attack_ready_", ""))
            metrics_file = os.path.join(WATCH_DIR, f"vanet_metrics_{cycle_id}.json")
            logger.info(f"Found missed cycle at startup: {cycle_id}")
            process_metrics(cycle_id, metrics_file, sentinel)
        except ValueError:
            pass

    # Start file watcher
    event_handler = MetricsEventHandler()
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=False)
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
