"""
evaluate_labeled.py - chạy detector.py trên dữ liệu của bạn và đánh giá ĐÚNG CÁCH:
  - Chỉ tính precision/recall trên contract CÓ NHÃN (labeled=True).
  - Contract chưa có nhãn được liệt kê riêng để bạn kiểm tra tay.
  - Báo cáo riêng từng loại tấn công.
Chạy:  python evaluate_labeled.py
"""
import json

import pandas as pd

from detector import EIP7702Detector

txs = pd.read_csv("transactions.csv")
contracts = json.load(open("contracts.json"))
det = EIP7702Detector(txs, contracts)

eoa = set(det.detect_eoa_targeted())
ca = det.detect_ca_targeted()
comp = det.detect_composite()

# ---- EOA-targeted: đánh giá trên delegate có nhãn ----
delegates = [a for a, c in contracts.items() if c.get("is_delegate")]
labeled = [a for a in delegates if contracts[a]["labeled"]]
unlabeled = [a for a in delegates if not contracts[a]["labeled"]]
tp = sum(1 for a in labeled if a in eoa and contracts[a]["is_malicious"])
fp = sum(1 for a in labeled if a in eoa and not contracts[a]["is_malicious"])
fn = sum(1 for a in labeled if a not in eoa and contracts[a]["is_malicious"])
tn = sum(1 for a in labeled if a not in eoa and not contracts[a]["is_malicious"])
prec = tp / (tp + fp) if tp + fp else 0.0
rec = tp / (tp + fn) if tp + fn else 0.0
f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0

# ---- tỉ lệ Attach trỏ tới contract bị detector báo ----
att = txs[txs["type"] == "Attach"]
n_att = len(att)
n_flag = int(att["to_addr"].isin(eoa).sum())

print("=== EOA-targeted ===")
print(f"Delegate: {len(delegates)} | có nhãn paper: {len(labeled)} | chưa có nhãn: {len(unlabeled)}")
print(f"TP={tp} FP={fp} FN={fn} TN={tn}  ->  precision={prec:.3f} recall={rec:.3f} F1={f1:.3f}")
print(f"Detector báo {len(eoa & set(delegates))}/{len(delegates)} delegate | "
      f"{n_flag}/{n_att} Attach trỏ tới delegate bị báo ({100 * n_flag / max(n_att, 1):.1f}%)")
print("Báo nhưng chưa có nhãn (cần kiểm tra tay):", [a for a in unlabeled if a in eoa])
print("False positive (paper không gán độc hại):", [a for a in labeled if a in eoa and not contracts[a]["is_malicious"]])

print("\n=== CA-targeted ===")
print("Số bộ (eoa, ca_1, ca_2) bị báo:", len(ca))
for t in ca[:5]:
    print("  ", t)

print("\n=== Composite ===")
print("Số bộ (victim, attacker, ca_1, ca_2, ca_v) bị báo:", len(comp))
for t in comp[:5]:
    print("  ", t)

json.dump({"eoa_targeted": sorted(eoa), "ca_targeted": [list(t) for t in ca],
           "composite": [list(t) for t in comp],
           "eoa_metrics": {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                           "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4)}},
          open("ket_qua.json", "w"), indent=2)
print("\nĐã lưu ket_qua.json")
