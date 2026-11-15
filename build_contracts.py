"""
build_contracts.py - đọc transactions.csv (do fetch_txs.py thu), tải bytecode qua RPC,
trích đặc trưng và tạo contracts.json cho detector.py.

Chạy:  python build_contracts.py
Cần:   $env:RPC_URL đã đặt, venv đang bật.
Nhãn:  lấy từ artifact của paper nếu có (chỉ để ĐỐI CHIẾU). Địa chỉ không có trong
       danh sách paper -> labeled=False (chưa có nhãn, KHÔNG phải lành).
"""
import json
import os
import time

import pandas as pd
import requests
from eth_utils import keccak

RPC = os.environ.get("RPC_URL", "DAN_RPC_URL_VAO_DAY")
LABEL_XLSX = "artifact/analysis_information/sa_contract_malicious.xlsx"
ZERO = "0x" + "0" * 40
DEAD = "0x000000000000000000000000000000000000dead"
session = requests.Session()


def rpc(method, params, tries=5):
    for k in range(tries):
        try:
            return session.post(RPC, json={"jsonrpc": "2.0", "id": 1, "method": method,
                                           "params": params}, timeout=30).json()
        except Exception:
            time.sleep(1.5 * (k + 1))
    return {"error": "request failed"}


def get_code(addr):
    r = rpc("eth_getCode", [addr, "latest"]).get("result", "0x") or "0x"
    try:
        return bytes.fromhex(r[2:])
    except ValueError:
        return b""


def accepts_eth(addr):
    """Gửi 1 wei, calldata rỗng: không revert nghĩa là có receive()/fallback() nhận ETH."""
    j = rpc("eth_call", [{"from": DEAD, "to": addr, "value": "0x1", "data": "0x"},
                         "latest", {DEAD: {"balance": "0xde0b6b3a7640000"}}])
    return "result" in j


def sel(sig):
    return keccak(text=sig)[:4].hex()


HOOKS = {
    "onERC721Received": "onERC721Received(address,address,uint256,bytes)",
    "onERC1155Received": "onERC1155Received(address,address,uint256,uint256,bytes)",
    "onERC1155BatchReceived": "onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)",
    "tokensReceived": "tokensReceived(address,address,address,uint256,bytes,bytes)",
    "onFlashLoan": "onFlashLoan(address,address,uint256,uint256,bytes)",
    "callFunction": "callFunction(address,(address,uint256),bytes)",
    "uniswapV2Call": "uniswapV2Call(address,uint256,uint256,bytes)",
    "uniswapV3FlashCallback": "uniswapV3FlashCallback(uint256,uint256,bytes)",
    "receiveFlashLoan": "receiveFlashLoan(address[],uint256[],uint256[],bytes)",
}
EXEC_OP = ["executeOperation(address[],uint256[],uint256[],address,bytes)",   # Aave v2
           "executeOperation(address,uint256,uint256,address,bytes)"]          # Aave v3
OUT = {
    "transfer": "transfer(address,uint256)",
    "transferFrom": "transferFrom(address,address,uint256)",
    "safeTransferFrom": "safeTransferFrom(address,address,uint256)",
}
HOOK_SEL = {sel(s): n for n, s in HOOKS.items()}
HOOK_SEL.update({sel(s): "executeOperation" for s in EXEC_OP})
OUT_SEL = {sel(s): n for n, s in OUT.items()}


def scan(code):
    i, push4, has_call = 0, set(), False
    while i < len(code):
        op = code[i]
        n = op - 0x5F if 0x60 <= op <= 0x7F else 0       # bỏ qua dữ liệu của PUSH
        if op == 0x63:
            push4.add(code[i + 1:i + 5].hex())
        if op in (0xF1, 0xF2, 0xF4):                      # CALL / CALLCODE / DELEGATECALL
            has_call = True
        i += 1 + n
    return push4, has_call


def load_labels():
    if not os.path.exists(LABEL_XLSX):
        print("Không thấy file nhãn paper -> mọi contract sẽ là chưa có nhãn")
        return {}
    lab = pd.read_excel(LABEL_XLSX)
    lab["addr"] = lab["delegated_address"].str.lower()
    return lab.groupby("addr")["matched"].apply(lambda s: bool((s == "matched").any())).to_dict()


def main():
    tx = pd.read_csv("transactions.csv")
    att = tx[tx["type"] == "Attach"]
    delegates = set(att["to_addr"]) - {ZERO}

    # contract tạo bởi EOA liên quan (cần cho CA-targeted / composite)
    cre = tx[tx["type"] == "Create"]
    n_created = cre.groupby("from_addr")["to_addr"].transform("count")
    related = set(cre[(n_created >= 2) | cre["from_addr"].isin(set(att["from_addr"]))]["to_addr"])
    targets = sorted(delegates | related)
    print(f"Delegate: {len(delegates)} | contract tạo liên quan: {len(related)} | cần tải code: {len(targets)}")

    labels = load_labels()
    contracts, no_code = {}, []
    for k, a in enumerate(targets):
        code = get_code(a)
        if not code or code[:3] == b"\xef\x01\x00":       # không có code (Finding 6) / là delegate khác
            no_code.append(a)
            continue
        push4, has_call = scan(code)
        hooks = sorted({n for s, n in HOOK_SEL.items() if s in push4})
        calls = [n for s, n in OUT_SEL.items() if s in push4]
        if has_call:
            calls.append("call")
        if accepts_eth(a):
            hooks.append("receive")                        # xấp xỉ cho receive/fallback
        contracts[a] = {"hooks": hooks, "external_calls": calls,
                        "labeled": a in labels,
                        "is_malicious": bool(labels.get(a, False)),
                        "is_delegate": a in delegates}
        if k % 50 == 0:
            print(k, "/", len(targets), flush=True)

    json.dump(contracts, open("contracts.json", "w"), indent=2)
    json.dump(no_code, open("no_code_delegates.json", "w"), indent=2)
    lab_n = sum(c["labeled"] for c in contracts.values())
    print(f"contracts.json: {len(contracts)} contract | có nhãn paper: {lab_n} | không có code: {len(no_code)}")


if __name__ == "__main__":
    main()
