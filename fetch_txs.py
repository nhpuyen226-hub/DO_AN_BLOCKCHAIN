"""
fetch_txs.py - thu thập giao dịch EIP-7702 on-chain qua JSON-RPC, ghi ra transactions.csv

Cách dùng (PowerShell, trong venv):
    $env:RPC_URL = "https://eth-mainnet.g.alchemy.com/v2/KEY_CUA_BAN"
    python fetch_txs.py 22500000 22510000

Chạy lại cùng lệnh sau khi bị ngắt: script tự đọc transactions.csv và chạy tiếp.
Cài thư viện:  pip install requests rlp eth-keys eth-utils "eth-hash[pycryptodome]"
"""
import csv
import os
import sys
import time

import requests
import rlp
from eth_keys import keys
from eth_utils import keccak

RPC = os.environ.get("RPC_URL", "DAN_RPC_URL_VAO_DAY")
CHAIN, CHAIN_ID = "ethereum", 1
OUT = "transactions.csv"
HEADER = ["type", "from_addr", "to_addr", "chain", "block", "tx_hash", "sponsor"]

START = int(sys.argv[1]) if len(sys.argv) > 2 else 22_500_000
END = int(sys.argv[2]) if len(sys.argv) > 2 else 22_510_000

session = requests.Session()


def rpc(method, params, tries=6):
    """Gọi JSON-RPC; trả (ok, result). ok=False nếu lỗi sau khi thử lại."""
    for k in range(tries):
        try:
            j = session.post(RPC, json={"jsonrpc": "2.0", "id": 1, "method": method,
                                        "params": params}, timeout=30).json()
            if "error" in j:
                msg = str(j["error"]).lower()
                if "not found" in msg or "not supported" in msg or "unsupported" in msg:
                    return False, None
            elif "result" in j:
                return True, j["result"]
        except Exception:
            pass
        time.sleep(1.5 * (k + 1))
    return False, None


def authority(a):
    """Khôi phục địa chỉ EOA đã ký authorization (EIP-7702: keccak(0x05 || rlp([chain_id, address, nonce])))."""
    try:
        cid = int(a["chainId"], 16)
        if cid not in (0, CHAIN_ID):
            return None                      # authorization không hợp lệ cho chain này
        payload = rlp.encode([cid, bytes.fromhex(a["address"][2:]), int(a["nonce"], 16)])
        digest = keccak(b"\x05" + payload)
        sig = keys.Signature(vrs=(int(a["yParity"], 16), int(a["r"], 16), int(a["s"], 16)))
        return sig.recover_public_key_from_msg_hash(digest).to_address().lower()
    except Exception:
        return None


def creation_addresses(block_number, txs):
    """Map tx_hash -> địa chỉ contract vừa tạo, chỉ cho các tx tạo contract."""
    result = {}
    ok, receipts = rpc("eth_getBlockReceipts", [hex(block_number)])
    if ok and receipts:
        for rc in receipts:
            if rc.get("contractAddress") and rc.get("status") == "0x1":
                result[rc["transactionHash"]] = rc["contractAddress"].lower()
        return result
    for tx in txs:                           # dự phòng: gọi từng receipt
        if tx["to"] is None:
            ok, rc = rpc("eth_getTransactionReceipt", [tx["hash"]])
            if ok and rc and rc.get("contractAddress") and rc.get("status") == "0x1":
                result[tx["hash"]] = rc["contractAddress"].lower()
    return result


# ---- nạp lại trạng thái nếu đã chạy trước đó ----
created_by, resume_from = {}, START
if os.path.exists(OUT):
    with open(OUT, newline="") as f:
        for r in csv.DictReader(f):
            resume_from = max(resume_from, int(r["block"]) + 1)
            if r["type"] == "Create":
                created_by[r["to_addr"]] = r["from_addr"]
    print(f"Chạy tiếp từ block {resume_from} (đã có {len(created_by)} contract)")
else:
    with open(OUT, "w", newline="") as f:
        csv.writer(f).writerow(HEADER)

failed = []
with open(OUT, "a", newline="") as f:
    w = csv.writer(f)
    n_attach = 0
    for n in range(resume_from, END + 1):
        ok, blk = rpc("eth_getBlockByNumber", [hex(n), True])
        if not ok or not blk:
            failed.append(n)
            continue
        txs = blk["transactions"]
        made = creation_addresses(n, txs) if any(t["to"] is None for t in txs) else {}

        for tx in txs:
            frm, to, h = tx["from"].lower(), tx["to"], tx["hash"]

            if tx.get("type") == "0x4":                          # giao dịch EIP-7702
                for a in tx.get("authorizationList", []):
                    auth = authority(a)
                    if auth:
                        w.writerow(["Attach", auth, a["address"].lower(), CHAIN, n, h, frm])
                        n_attach += 1

            if to is None:                                       # tạo contract
                ca = made.get(h)
                if ca:
                    created_by[ca] = frm
                    w.writerow(["Create", frm, ca, CHAIN, n, h, ""])
            elif created_by.get(to.lower()) == frm:              # người tạo gọi contract của mình
                w.writerow(["Invoke", frm, to.lower(), CHAIN, n, h, ""])

        if n % 200 == 0:
            f.flush()
            print(f"block {n} | Attach đã thu: {n_attach} | block lỗi: {len(failed)}", flush=True)

if failed:
    with open("failed_blocks.txt", "w") as f:
        f.write("\n".join(map(str, failed)))
    print("Có", len(failed), "block lỗi, xem failed_blocks.txt (chạy lại để thử lại)")
print("Xong. File:", OUT)
