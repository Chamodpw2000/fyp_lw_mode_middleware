import os

# ─── Paths ───────────────────────────────────────────────────────────────────
BASE_DIR        = os.path.expanduser("~/vanet_attack_detector")
LOG_FILE        = os.path.join(BASE_DIR, "logs/detector.log")
WATCH_DIR       = "/tmp"

# ─── Fabric Paths ────────────────────────────────────────────────────────────
FABRIC_BASE     = os.path.expanduser("~/fabric/fabric-samples")
TEST_NETWORK    = os.path.join(FABRIC_BASE, "test-network")
BIN_DIR         = os.path.join(FABRIC_BASE, "bin")
CFG_DIR         = os.path.join(FABRIC_BASE, "config")

ORG1_BASE       = os.path.join(TEST_NETWORK,
                 "organizations/peerOrganizations/controllers.example.com")

TLS_CERT_ORG1   = os.path.join(ORG1_BASE,
                  "peers/controller0.controllers.example.com/tls/ca.crt")

MSP_PATH_ORG1   = os.path.join(ORG1_BASE,
                  "users/Admin@controllers.example.com/msp")

TLS_CERT_ORG2   = os.path.join(TEST_NETWORK,
                  "organizations/peerOrganizations/org2.example.com"
                  "/peers/peer0.org2.example.com/tls/ca.crt")

ORDERER_CA      = os.path.join(TEST_NETWORK,
                  "organizations/ordererOrganizations/example.com"
                  "/orderers/orderer.example.com/msp/tlscacerts"
                  "/tlsca.example.com-cert.pem")

# ─── Fabric Network ──────────────────────────────────────────────────────────
CHANNEL_NAME    = "mychannel"
CHAINCODE_NAME  = "attackdetector"
PEER_ORG1       = "localhost:7051"
PEER_ORG2       = "localhost:9051"
ORDERER         = "localhost:7050"
