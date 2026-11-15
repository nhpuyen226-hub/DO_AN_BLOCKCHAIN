import json
import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score

# Bảng 1: Các hàm nhận tài sản và lệnh chuyển tài sản (EOA-targeted)
INBOUND_HOOKS = {
    "receive", "fallback", "onERC721Received",
    "onERC1155Received", "onERC1155BatchReceived", "tokensReceived"
}
OUTBOUND_CALLS = {
    "send", "transfer", "transferFrom",
    "safeTransferFrom", "safeTransfer", "call"
}

# Bảng 2: Các hàm callback của giao thức Flashloan (CA-targeted & Composite)
FLASHLOAN_HOOKS = {
    "onFlashLoan", "callFunction", "executeOperation",
    "uniswapV2Call", "uniswapV3FlashCallback", "receiveFlashLoan"
}


class EIP7702Detector:
    def __init__(self, transactions_df: pd.DataFrame, contracts_info: dict):
        self.txs = transactions_df
        self.contracts = contracts_info

        # Phân nhóm toàn bộ lịch sử giao dịch theo địa chỉ gửi
        self.creates = self._group_txs("Create")
        self.attaches = self._group_txs("Attach")
        self.invokes = self._group_txs("Invoke")

    def _group_txs(self, tx_type: str) -> dict:
        subset = self.txs[self.txs["type"] == tx_type]
        return subset.groupby("from_addr")["to_addr"].apply(list).to_dict()

    def _has_call_edge(self, caller: str, callee: str) -> bool:
        """Kiểm tra quan hệ gọi hàm giữa hai contract (MATCHCALLSIG)."""
        caller_calls = set(self.contracts.get(caller, {}).get("external_calls", []))
        callee_funcs = set(self.contracts.get(callee, {}).get("public_funcs", []))
        if not callee_funcs:
            return len(caller_calls) > 0
        return bool(caller_calls & callee_funcs)

    def detect_eoa_targeted(self) -> list:
        """Quy tắc 1 (Mục 4.1): Phát hiện EOA-targeted attack."""
        malicious_cas = set()
        attach_txs = self.txs[self.txs["type"] == "Attach"]

        for _, row in attach_txs.iterrows():
            ca = row["to_addr"]
            info = self.contracts.get(ca)
            if not info:
                continue

            hooks = set(info.get("hooks", []))
            calls = set(info.get("external_calls", []))

            if (hooks & INBOUND_HOOKS) and (calls & OUTBOUND_CALLS):
                malicious_cas.add(ca)

        return sorted(malicious_cas)

    def detect_ca_targeted(self) -> list:
        """Quy tắc 2 & 3 (Mục 4.2): Phát hiện CA-targeted attack."""
        detected = set()

        for eoa, created_cas in self.creates.items():
            if len(created_cas) < 2:
                continue

            for ca_1 in self.attaches.get(eoa, []):
                for ca_2 in self.invokes.get(eoa, []):
                    if ca_1 in created_cas and ca_2 in created_cas and ca_1 != ca_2:
                        c1 = self.contracts.get(ca_1, {})
                        c2 = self.contracts.get(ca_2, {})

                        has_flashloan = bool(set(c2.get("hooks", [])) & FLASHLOAN_HOOKS)
                        c2_calls = len(c2.get("external_calls", [])) > 0
                        c1_calls = len(c1.get("external_calls", [])) > 0
                        callback_match = self._has_call_edge(ca_2, ca_1)

                        if has_flashloan and c2_calls and c1_calls and callback_match:
                            detected.add((eoa, ca_1, ca_2))

        return sorted(detected)

    def detect_composite(self) -> list:
        """Quy tắc 4 & 5 (Mục 4.3): Phát hiện Composite attack."""
        detected = set()

        for eoa_v, victim_cas in self.creates.items():
            if not victim_cas:
                continue

            for ca_1 in self.attaches.get(eoa_v, []):
                for eoa_a, attacker_cas in self.creates.items():
                    if eoa_a == eoa_v or ca_1 not in attacker_cas:
                        continue

                    for ca_2 in self.invokes.get(eoa_a, []):
                        if ca_2 in attacker_cas and ca_2 != ca_1:
                            c2 = self.contracts.get(ca_2, {})
                            has_flashloan = bool(set(c2.get("hooks", [])) & FLASHLOAN_HOOKS)
                            edge_2_to_1 = self._has_call_edge(ca_2, ca_1)

                            for ca_v in victim_cas:
                                edge_1_to_v = self._has_call_edge(ca_1, ca_v)
                                if has_flashloan and edge_2_to_1 and edge_1_to_v:
                                    detected.add((eoa_v, eoa_a, ca_1, ca_2, ca_v))

        return sorted(detected)

    def evaluate(self) -> dict:
        """Chạy toàn bộ detector và tính Precision/Recall nếu có nhãn ground truth."""
        eoa_res = self.detect_eoa_targeted()
        ca_res = self.detect_ca_targeted()
        comp_res = self.detect_composite()

        predicted = set(eoa_res)
        for _, ca_1, ca_2 in ca_res:
            predicted.update([ca_1, ca_2])
        for _, _, ca_1, ca_2, _ in comp_res:
            predicted.update([ca_1, ca_2])

        all_cas = sorted(self.contracts.keys())
        y_true = [1 if self.contracts[ca].get("is_malicious", False) else 0 for ca in all_cas]
        y_pred = [1 if ca in predicted else 0 for ca in all_cas]

        return {
            "eoa_targeted": eoa_res,
            "ca_targeted": [list(x) for x in ca_res],
            "composite": [list(x) for x in comp_res],
            "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
            "recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
            "f1": round(f1_score(y_true, y_pred, zero_division=0), 4),
        }


if __name__ == "__main__":
    txs = pd.read_csv("transactions.csv")
    with open("contracts.json", "r", encoding="utf-8") as f:
        contracts = json.load(f)

    detector = EIP7702Detector(txs, contracts)
    results = detector.evaluate()
    print(json.dumps(results, indent=2))