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
import socket
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
# Unix-domain control socket exposed by the ns-3 simulation.
NS3_CONTROL_SOCKET = "/tmp/vanet_verify.sock"

# Stop waiting if ns-3 does not reply within this time.
NS3_SOCKET_TIMEOUT_SECONDS = 2.0

# Retry when ns-3 is temporarily unavailable.
NS3_REVOKE_RETRIES = 3
NS3_RETRY_DELAY_SECONDS = 0.2

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


# ─── Ground-Truth Configuration ──────────────────────────────────────────────
# Edit these to match your simulation setup before each run.
# total_nodes: total number of routing-layer nodes (NOT global ns-3 node count).
# *_ATTACKER_IDS: the routing-layer node_ids that are true attackers.

TOTAL_NODES = 321

GROUND_TRUTH_ATTACKERS = {
    "Interleaved_Jamming_Attack": [30, 111, 123, 143, 240, 251, 1, 75, 188, 38, 155, 198, 250, 67, 239, 261, 6, 118, 130, 258, 42, 79, 259, 260, 134, 44, 108, 141, 194, 36],   
    "Split_Path_Attack":          [5, 12, 27, 34, 41, 58, 63, 72, 89, 96, 104, 113, 127, 138, 145, 152, 169, 176, 183, 197, 205, 214, 228, 236, 249, 257, 268, 274, 289, 301],  
    "Flow_Stretching_Attack":     [4, 11, 22, 31, 48, 59, 66, 77, 84, 95, 106, 115, 122, 133, 144, 151, 168, 175, 182, 195, 208, 219, 226, 233, 248, 255, 262, 279, 296, 310], 
}

# ─── Cumulative Detection State (updated every cycle) ────────────────────────
# Stores SETS of node_ids, not counts, so the same node cannot be
# counted twice across cycles regardless of how many cycles it appears in.
#
# Per-attack tracking:
#   _ever_detected[attack_type]  = node_ids detected as that attack type (ever)
#   _ever_evaluated[attack_type] = node_ids sent to chaincode in any cycle
#
# Overall tracking (attack-type-agnostic):
#   _overall_ever_detected = node_ids detected as ANY attack type (ever)
#   _overall_ever_evaluated = node_ids sent to chaincode in any cycle

_ever_detected: dict = {at: set() for at in GROUND_TRUTH_ATTACKERS}
_ever_evaluated: dict = {at: set() for at in GROUND_TRUTH_ATTACKERS}

_overall_ever_detected:  set = set()
_overall_ever_evaluated: set = set()
def _compute_and_display_mcc(cycle_id: int, detections: list, nodes: list) -> None:
    """
    Updates cumulative per-attack and overall detection sets, then prints
    the TP/FP/TN/FN table and MCC values.

    Uses sets of node_ids (not integer counters) so that the same node
    appearing in multiple cycles is never counted more than once.

    detections : list of dicts returned by detect_attacks()
    nodes      : list of node dicts sent to the chaincode this cycle
    """

    # ── Node IDs present in this cycle's CSV ─────────────────────────────────
    cycle_evaluated = {int(n["node_id"]) for n in nodes}

    # ── Detections this cycle, grouped by attack type ─────────────────────────
    detected_this_cycle: dict = {at: set() for at in GROUND_TRUTH_ATTACKERS}
    all_detected_this_cycle: set = set()

    for d in detections or []:
        attack_type = d.get("attack_type", "")
        node_id     = int(d.get("node_id", -1))

        if attack_type in detected_this_cycle:
            detected_this_cycle[attack_type].add(node_id)

        # For overall tracking, record every detected node regardless of label.
        all_detected_this_cycle.add(node_id)

    # ── Update per-attack cumulative sets ─────────────────────────────────────
    for attack_type in GROUND_TRUTH_ATTACKERS:
        # Accumulate every node seen and every node flagged (ever).
        _ever_evaluated[attack_type].update(cycle_evaluated)
        _ever_detected[attack_type].update(detected_this_cycle[attack_type])

    # ── Update overall cumulative sets ────────────────────────────────────────
    _overall_ever_evaluated.update(cycle_evaluated)
    _overall_ever_detected.update(all_detected_this_cycle)

    # ── Print results ─────────────────────────────────────────────────────────
    _print_mcc_table(cycle_id)


def _print_mcc_table(cycle_id: int) -> None:
    """
    Derives TP/FP/TN/FN from cumulative node-ID sets and prints the table.

    Because we store sets of node_ids (not running integer totals), every
    node is counted exactly once no matter how many cycles it has appeared in.
    """

    SEP   = "─" * 72
    LABEL = {
        "Interleaved_Jamming_Attack": "Interleaved Jamming",
        "Split_Path_Attack":          "Split Path         ",
        "Flow_Stretching_Attack":     "Flow Stretching    ",
    }

    logger.info(SEP)
    logger.info(f"  MODEL PERFORMANCE — Cumulative after cycle {cycle_id}")
    logger.info(SEP)
    logger.info(
        f"  {'Attack Type':<22} {'TP':>5} {'FP':>5} "
        f"{'TN':>6} {'FN':>5}  {'MCC':>7}"
    )
    logger.info(SEP)

    for attack_type, true_ids in GROUND_TRUTH_ATTACKERS.items():
        evaluated  = _ever_evaluated[attack_type]   # all nodes seen so far
        detected   = _ever_detected[attack_type]    # all nodes flagged so far

        true_set     = set(true_ids) & evaluated    # true attackers we have seen
        negative_set = evaluated - true_set         # innocent nodes we have seen

        tp = len(true_set     & detected)           # seen attacker, was flagged
        fp = len(negative_set & detected)           # seen innocent, wrongly flagged
        fn = len(true_set     - detected)           # seen attacker, never flagged
        tn = len(negative_set - detected)           # seen innocent, never flagged

        numerator   = (tp * tn) - (fp * fn)
        denominator = ((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)) ** 0.5
        mcc         = (numerator / denominator) if denominator != 0 else 0.0

        label = LABEL.get(attack_type, attack_type)
        logger.info(
            f"  {label:<22} {tp:>5} {fp:>5} {tn:>6} {fn:>5}  {mcc:>7.4f}"
        )

    # ── Overall row (attack-type-agnostic) ───────────────────────────────────
    all_true_ids = set()
    for ids in GROUND_TRUTH_ATTACKERS.values():
        all_true_ids.update(ids)

    o_evaluated    = _overall_ever_evaluated
    o_detected     = _overall_ever_detected
    o_true_set     = all_true_ids & o_evaluated
    o_negative_set = o_evaluated  - o_true_set

    otp = len(o_true_set     & o_detected)
    ofp = len(o_negative_set & o_detected)
    ofn = len(o_true_set     - o_detected)
    otn = len(o_negative_set - o_detected)

    o_numerator   = (otp * otn) - (ofp * ofn)
    o_denominator = ((otp + ofp) * (otp + ofn) * (otn + ofp) * (otn + ofn)) ** 0.5
    o_mcc         = (o_numerator / o_denominator) if o_denominator != 0 else 0.0

    logger.info("─" * 72)
    logger.info(
        f"  {'All Attacks (Overall)':<22} {otp:>5} {ofp:>5} {otn:>6} {ofn:>5}  {o_mcc:>7.4f}"
    )
    logger.info(SEP)

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


# ─── ns-3 Revocation Client ───────────────────────────────────────────────────

def request_ns3_revocation(routing_node_id: int) -> str:
    """
    Sends one revocation request to ns-3.

    routing_node_id is the node_id returned by the attack-detection
    chaincode. Do not add 2 here. The ns-3 REVOKE_NODE handler performs
    the conversion from routing ID to global ns-3 ID.
    """

    if routing_node_id < 0:
        raise ValueError("routing_node_id cannot be negative")

    command = f"REVOKE_NODE:{routing_node_id}\n".encode("utf-8")
    last_error = None

    for attempt in range(1, NS3_REVOKE_RETRIES + 1):
        try:
            # Open one connection for one REVOKE_NODE command.
            with socket.socket(
                socket.AF_UNIX,
                socket.SOCK_STREAM
            ) as client:

                client.settimeout(NS3_SOCKET_TIMEOUT_SECONDS)
                client.connect(NS3_CONTROL_SOCKET)
                client.sendall(command)

                response = client.recv(1024)

            if not response:
                raise ConnectionError(
                    "ns-3 closed the socket without sending a response"
                )

            status = response.decode("utf-8").strip()

        except (OSError, ConnectionError) as exc:
            last_error = exc

            if attempt < NS3_REVOKE_RETRIES:
                logger.warning(
                    f"Node {routing_node_id}: revocation attempt "
                    f"{attempt}/{NS3_REVOKE_RETRIES} failed: "
                    f"{exc}; retrying"
                )

                time.sleep(NS3_RETRY_DELAY_SECONDS)
                continue

            break

        # ns-3 successfully accepted the request.
        if status.startswith(("QUEUED", "ALREADY_QUEUED")):
            return status

        # The connection worked, but ns-3 rejected the command.
        # Retrying will not correct an invalid node ID or command.
        raise RuntimeError(
            f"ns-3 rejected the revocation request: {status}"
        )

    raise RuntimeError(
        f"could not revoke routing node {routing_node_id}: "
        f"{last_error}"
    )


def revoke_detected_attackers(
    cycle_id: int,
    detections: list
) -> None:
    """
    Sends one REVOKE_NODE command for each unique detected node.

    A node may appear several times in detections because the same node
    can be detected in several flows. The node is sent to ns-3 only once
    per detection cycle.
    """

    unique_node_ids = []
    seen_node_ids = set()

    # Extract and validate each detected node ID.
    for detection in detections or []:
        try:
            node_id = int(detection["node_id"])

        except (KeyError, TypeError, ValueError):
            logger.error(
                f"Cycle {cycle_id}: detection contains an invalid "
                f"node_id: {detection!r}"
            )
            continue

        if node_id < 0:
            logger.error(
                f"Cycle {cycle_id}: refusing negative node_id "
                f"{node_id}"
            )
            continue

        # The same node can occur in several detection records.
        if node_id not in seen_node_ids:
            seen_node_ids.add(node_id)
            unique_node_ids.append(node_id)

    if not unique_node_ids:
        logger.warning(
            f"Cycle {cycle_id}: detections contained no valid "
            f"node IDs to revoke"
        )
        return

    successful = 0
    failed = 0

    # Send one socket command per unique attacker.
    for node_id in unique_node_ids:
        try:
            status = request_ns3_revocation(node_id)
            successful += 1

            logger.warning(
                f"Cycle {cycle_id}: requested revocation of routing "
                f"node {node_id}; ns-3 response: {status}"
            )

        except Exception as exc:
            failed += 1

            # A failure for one attacker must not prevent the remaining
            # attackers from being sent to ns-3.
            logger.error(
                f"Cycle {cycle_id}: failed to request revocation of "
                f"routing node {node_id}: {exc}"
            )

    logger.info(
        f"Cycle {cycle_id}: revocation requests complete — "
        f"successful={successful}, "
        f"failed={failed}, "
        f"unique_attackers={len(unique_node_ids)}"
    )
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
    3. Log and save detections
    4. Request ns-3 revocation of detected attackers
    5. Cleanup temporary sentinel file
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

            # Tell ns-3 to remove every unique detected attacker from
            # future routing decisions.
            revoke_detected_attackers(
                cycle_id=cycle_id,
                detections=detections
            )

        # ── Step 3b: Compute and display cumulative MCC ───────────────────────
        # This runs whether or not there were detections, so you see MCC=1.0
        # on clean cycles too (all TN, no FP/FN).
        _compute_and_display_mcc(cycle_id, detections or [], nodes)

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
    logger.info(f"ns-3 control socket: {NS3_CONTROL_SOCKET}")

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
