import subprocess
import os
import json
import logging
from config import (
    BIN_DIR, CFG_DIR, CHANNEL_NAME, CHAINCODE_NAME,
    PEER_ORG1, PEER_ORG2, ORDERER,
    TLS_CERT_ORG1, TLS_CERT_ORG2, MSP_PATH_ORG1, ORDERER_CA
)

logger = logging.getLogger(__name__)


def _get_fabric_env() -> dict:
    """Builds environment variables for peer CLI commands."""
    env = os.environ.copy()
    env.update({
        "PATH":                        f"{BIN_DIR}:{env.get('PATH', '')}",
        "FABRIC_CFG_PATH":             CFG_DIR,
        "CORE_PEER_TLS_ENABLED":       "true",
        "CORE_PEER_LOCALMSPID":        "ControllersMSP",
        "CORE_PEER_ADDRESS":           PEER_ORG1,
        "CORE_PEER_TLS_ROOTCERT_FILE": TLS_CERT_ORG1,
        "CORE_PEER_MSPCONFIGPATH":     MSP_PATH_ORG1,
    })
    return env


def detect_attacks(cycle_id: int, sim_time: float, nodes: list) -> list:
    """
    Invokes DetectAttacks chaincode function.
    
    nodes is a list of dicts:
    [
        {"node_id": 5, "flow_id": 1, "flow_fraction": 0.7, "pdrn": 0.6 , "inbound_ratio": 0.5},
        ...
    ]
    
    Returns list of detection dicts or empty list if none detected.
    """

    # Serialize nodes array to JSON string
    # This becomes the third argument to DetectAttacks
    nodes_json = json.dumps(nodes, separators=(',', ':'))

    args_json = (
        f'{{"function":"DetectAttacks",'
        f'"Args":["{cycle_id}","{sim_time}",{json.dumps(nodes_json)}]}}'
    )

    cmd = [
        "peer", "chaincode", "invoke",
        "-o", ORDERER,
        "--ordererTLSHostnameOverride", "orderer.example.com",
        "--tls",
        "--cafile", ORDERER_CA,
        "-C", CHANNEL_NAME,
        "-n", CHAINCODE_NAME,
        "--peerAddresses", PEER_ORG1,
        "--tlsRootCertFiles", TLS_CERT_ORG1,
        "--peerAddresses", PEER_ORG2,
        "--tlsRootCertFiles", TLS_CERT_ORG2,
        "-c", args_json
    ]

    try:
        result = subprocess.run(
            cmd,
            env=_get_fabric_env(),
            capture_output=True,
            text=True,
            timeout=30
        )

        output = result.stderr + result.stdout

        if result.returncode == 0 and "status:200" in output:
            # Extract payload from output
            # Output looks like: status:200 payload:"[{...}]"
            import re
            match = re.search(r'payload:"(.*)"', output)
            if match:
                payload_str = match.group(1)
                # Unescape the JSON string
                payload_str = payload_str.replace('\\"', '"')
                detections = json.loads(payload_str)
                logger.info(f"DetectAttacks success | "
                           f"Cycle: {cycle_id} | "
                           f"Detections: {len(detections)}")
                return detections
            return []
        else:
            logger.error(f"DetectAttacks failed | "
                        f"returncode: {result.returncode} | "
                        f"output: {output}")
            return []

    except subprocess.TimeoutExpired:
        logger.error(f"DetectAttacks timeout for cycle {cycle_id}")
        return []
    except Exception as e:
        logger.error(f"DetectAttacks exception: {e}")
        return []


def get_detections(cycle_id: int) -> dict:
    """Queries GetDetections for a specific cycle."""

    args_json = f'{{"function":"GetDetections","Args":["{cycle_id}"]}}'

    cmd = [
        "peer", "chaincode", "query",
        "-C", CHANNEL_NAME,
        "-n", CHAINCODE_NAME,
        "-c", args_json
    ]

    try:
        result = subprocess.run(
            cmd,
            env=_get_fabric_env(),
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode == 0:
            return json.loads(result.stdout.strip())
        else:
            logger.error(f"GetDetections failed: {result.stderr}")
            return None

    except Exception as e:
        logger.error(f"GetDetections exception: {e}")
        return None
