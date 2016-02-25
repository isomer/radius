#!/usr/bin/env python
import sys
import hashlib

DO_EAP=True

radius_txn = {}

# eap_session => list of (ts, radius_txn_state)
eap_txn = {}

TIMEOUT="TIMEOUT"
TIMEOUT_RAD = TIMEOUT + "-1"
TIMEOUT_EAP = TIMEOUT + "-2"

EAP_TIMEOUT=40.0
RAD_TIMEOUT=30.0
EAP_EXPIRY=60.0
RAD_EXPIRY=60.0

def output_eap_session(eap_session):
    if sorted(eap_txn[eap_session])[-1][1] == "Access-Challenge":
        raise Exception("Unexpected")
    print "EAP", eap_session, \
            "%.03f" % (eap_txn[eap_session][-1][0] - eap_txn[eap_session][0][0]), \
            "".join({
                "Access-Accept": "a",
                "Access-Reject": "r",
                "Access-Challenge": "c",
                TIMEOUT_RAD: "R",
                TIMEOUT_EAP: "E",
                }[x] for _, x in sorted(eap_txn[eap_session]))

def expire_eap(now):
    expired = []
    for i in eap_txn:
        ts, laststate = eap_txn[i][-1]
        if not laststate.startswith(TIMEOUT) and now - ts > EAP_TIMEOUT:
            eap_txn[i].append((ts, TIMEOUT_EAP))
            if laststate == "Access-Challenge":
                output_eap_session(i)
        elif laststate == TIMEOUT_EAP and now - ts > EAP_EXPIRY:
            expired.append(i)
    for i in expired:
        del eap_txn[i] # Expire the flow


def push_eap_state(ip_session, mid, ts, code):
    rad_session = ip_session + "-" + mid
    txn = radius_txn[rad_session]
    txn["state"] = code
    eap_session = ip_session + " " + " ".join(txn[x] for x in (
        "user", "nas_port", "nas_port_type", "nas_port_id",
        "calling_station_id", "called_station_id"))
    eap_txn[eap_session] = eap_txn.get(eap_session, []) + [(ts, code)]
    _, lastcode = sorted(eap_txn[eap_session])[-1]
    if lastcode != "Access-Challenge":
        output_eap_session(eap_session)


def output_rad_session(rad_session, code):
    txn = radius_txn[rad_session]
    print "RTX %.03f" % (ts - txn["ts"]),  \
            rad_session,                \
            txn["user"],               \
            txn["nas_port"],           \
            txn["nas_port_type"],      \
            txn["nas_port_id"],        \
            txn["calling_station_id"], \
            txn["called_station_id"],  \
            txn["state"],              \
            code


def expire_rad(now):
    expiry = []
    for i in radius_txn:
        if now - radius_txn[i]["ts"] > RAD_TIMEOUT:
            if radius_txn[i]["state"] == "Access-Request":
                src, dst, mid = i.split("-")
                rad_session = "-".join((src, dst))
                output_rad_session(i, "(none)")
                push_eap_state(rad_session, mid, radius_txn[i]["ts"], TIMEOUT_RAD)
        if now - radius_txn[i]["ts"] > RAD_EXPIRY:
            expiry.append(i)
    for i in expiry:
        del radius_txn[i]

lastexpire = 0
for i in sys.stdin:
    try:
        (ts, src, dst, code, mid, user, nas_port, nas_port_type, nas_port_id,
        calling_station_id, called_station_id) = i.strip().split(" ", 10)
    except:
        print "!!! Unparsable line:",repr(i)
        continue
    try:
        ts = float(ts)
        _, user = user.split(":", 1)
        _, code = code.split(":", 1)
        _, nas_port = nas_port.split(":", 1)
        _, nas_port_type = nas_port_type.split(":", 1)
        _, nas_port_id = nas_port_id.split(":", 1)
        _, calling_station_id = calling_station_id.split(":", 1)
        _, called_station_id = called_station_id.split(":", 1)
    except:
        print "!!! Unparsable line:", repr(i)
        continue
    if code in ("Access-Reject", "Access-Challenge", "Access-Accept"):
        ip_session = dst + "-" + src
    elif code in ("Access-Request", "Status-Server"):
        ip_session = src + "-" + dst
    else:
        print "UNKNOWN CODE:", code
        continue
    rad_session = ip_session + "-" + mid
    print "RAD", ts, rad_session, user, code, nas_port, nas_port_type, nas_port_id, calling_station_id, called_station_id
    if code == "Access-Request":
        radius_txn[rad_session] = {
                "ts": ts,
                "user": user,
                "code": code,
                "nas_port": nas_port,
                "nas_port_type": nas_port_type,
                "nas_port_id": nas_port_id,
                "calling_station_id": calling_station_id,
                "called_station_id" : called_station_id,
                "state" : code,
        }
    elif code in ["Access-Challenge", "Access-Reject", "Access-Accept"]:
        if rad_session in radius_txn:
            output_rad_session(rad_session, code)
            if DO_EAP:
                push_eap_state(ip_session, mid, ts, code)
        else:
            print "Missing initial packet:", rad_session
    else:
        print "??? Unknown code:", code
    if ts - lastexpire > 5:
        expire_rad(ts)
        if DO_EAP:
            expire_eap(ts)
        lastexpire = ts
