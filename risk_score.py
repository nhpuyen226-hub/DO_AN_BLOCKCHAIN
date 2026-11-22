"""
risk_score.py - chấm điểm rủi ro (0-100) cho từng delegate contract EIP-7702.

Dùng lại dữ liệu và detector có sẵn:
    transactions.csv, contracts.json  +  detector.EIP7702Detector

Điểm = tổng có trọng số của 3 nhóm tín hiệu (cắt trần ở 100):
    A. Static    - năng lực của bytecode (hook nhận tài sản, lệnh chuyển ra, flashloan)
    B. Behaviour - cách delegate được dùng on-chain (sponsor, burst, người tạo)
    C. Rules     - delegate có bị các luật 1-5 của detector báo hay không

Mỗi điểm đều có "lý do" đi kèm (explain) để đưa vào báo cáo.

Chạy:  python risk_score.py
Ra:    risk_scores.json, risk_scores.csv, eoa_exposure.csv
"""
import json
import math

import pandas as pd

from detector import EIP7702Detector, FLASHLOAN_HOOKS

ZERO = "0x" + "0" * 40

# ----------------------------------------------------------------------------
# Trọng số (do người thiết kế đặt, KHÔNG fit từ nhãn; chỉnh ở đây nếu cần)
# ----------------------------------------------------------------------------
W = {
    # A. Static
    "inbound_hook":   6,    # có receive / hook nhận ETH, NFT, token
    "token_callback": 4,    # thêm hook ERC721/1155/777 (nhận NFT/token tuỳ ý)
    "token_out":     16,    # selector chuyển token tường minh (transfer/transferFrom/safeTransferFrom)
    "generic_call":   4,    # chỉ có CALL/DELEGATECALL chung chung (rất nhiều ví hợp lệ cũng có)
    "flashloan":      8,    # có hook flashloan
    # B. Behaviour
    "sponsor_conc":  14,    # 1 sponsor đứng sau nhiều nạn nhân khác nhau
    "sponsored":      6,    # tỉ lệ authorization do bên thứ ba gửi hộ
    "burst":          6,    # attach dồn cục trong thời gian ngắn
    "creator_ctrl":  10,    # người tạo delegate cũng là người gửi/ký attach vào nó
    # C. Rules
    "rule_eoa":       6,
    "rule_ca":       12,
    "rule_comp":     12,
}
TOKEN_CB = {"onERC721Received", "onERC1155Received", "onERC1155BatchReceived", "tokensReceived"}
TOKEN_OUT = {"transfer", "transferFrom", "safeTransferFrom", "safeTransfer"}
BURST_WINDOW = 20      # số block của cửa sổ burst
MIN_N_BEHAVIOUR = 3    # ít hơn ngần này attach thì không đánh giá tín hiệu hành vi (quá ít bằng chứng)

TIERS = [(50, "HIGH"), (25, "MEDIUM"), (0, "LOW")]


def tier_of(score: float) -> str:
    for thr, name in TIERS:
        if score >= thr:
            return name
    return "LOW"


# ----------------------------------------------------------------------------
# Đặc trưng hành vi từ transactions.csv
# ----------------------------------------------------------------------------
def behaviour_features(att: pd.DataFrame, creates: pd.DataFrame, delegate: str) -> dict:
    a = att[att["to_addr"] == delegate]
    n = len(a)
    victims = a["from_addr"].nunique()
    sponsors = a["sponsor"].nunique()
    third_party = (a["from_addr"] != a["sponsor"]).sum()

    # sponsor concentration: 1 - (số sponsor / số nạn nhân), nhân hệ số quy mô
    conc = 0.0
    if victims >= MIN_N_BEHAVIOUR:
        conc = (1 - sponsors / victims) * min(1.0, victims / 10)

    # burst: tỉ lệ attach nằm trong cửa sổ BURST_WINDOW block dày nhất
    burst = 0.0
    if n >= MIN_N_BEHAVIOUR:
        blocks = sorted(a["block"].tolist())
        best, j = 0, 0
        for i, b in enumerate(blocks):
            while b - blocks[j] > BURST_WINDOW:
                j += 1
            best = max(best, i - j + 1)
        burst = best / n

    # người tạo delegate có tham gia attach vào nó không
    creator = creates.loc[creates["to_addr"] == delegate, "from_addr"]
    controlled = False
    if len(creator):
        c = creator.iloc[0]
        controlled = bool(((a["from_addr"] == c) | (a["sponsor"] == c)).any())

    return {
        "n_attach": int(n),
        "n_victims": int(victims),
        "n_sponsors": int(sponsors),
        "third_party_ratio": round(float(third_party / n), 3) if n else 0.0,
        "sponsor_conc": round(conc, 3),
        "burst": round(burst, 3),
        "creator_ctrl": controlled,
    }


# ----------------------------------------------------------------------------
# Chấm điểm 1 delegate
# ----------------------------------------------------------------------------
def score_delegate(info: dict, beh: dict, hit_eoa: bool, hit_ca: bool, hit_comp: bool):
    hooks, calls = set(info.get("hooks", [])), set(info.get("external_calls", []))
    pts, why = {}, []

    def add(key, value, reason):
        if value > 0:
            pts[key] = round(value, 2)
            why.append(f"+{value:.1f} {reason}")

    # A. Static
    if hooks & ({"receive"} | TOKEN_CB):
        add("inbound_hook", W["inbound_hook"], "có hook nhận tài sản")
    if hooks & TOKEN_CB:
        add("token_callback", W["token_callback"], "nhận NFT/token qua callback")
    if calls & TOKEN_OUT:
        add("token_out", W["token_out"], f"gọi chuyển token tường minh ({', '.join(sorted(calls & TOKEN_OUT))})")
    elif "call" in calls:
        add("generic_call", W["generic_call"], "chỉ có CALL chung chung")
    if hooks & FLASHLOAN_HOOKS:
        add("flashloan", W["flashloan"], "có hook flashloan")

    # B. Behaviour
    add("sponsor_conc", W["sponsor_conc"] * beh["sponsor_conc"],
        f"{beh['n_victims']} nạn nhân nhưng chỉ {beh['n_sponsors']} sponsor")
    if beh["n_attach"] >= MIN_N_BEHAVIOUR:
        add("sponsored", W["sponsored"] * beh["third_party_ratio"],
            f"{beh['third_party_ratio']:.0%} authorization do bên thứ ba gửi")
    add("burst", W["burst"] * beh["burst"], f"{beh['burst']:.0%} attach dồn trong {BURST_WINDOW} block")
    if beh["creator_ctrl"]:
        add("creator_ctrl", W["creator_ctrl"], "người tạo delegate cũng attach/sponsor vào nó")

    # C. Rules
    if hit_eoa:
        add("rule_eoa", W["rule_eoa"], "bị Quy tắc 1 (EOA-targeted) báo")
    if hit_ca:
        add("rule_ca", W["rule_ca"], "tham gia chuỗi CA-targeted (Quy tắc 2-3)")
    if hit_comp:
        add("rule_comp", W["rule_comp"], "tham gia chuỗi Composite (Quy tắc 4-5)")

    score = min(100.0, sum(pts.values()))
    return round(score, 1), pts, why


# ----------------------------------------------------------------------------
def main():
    txs = pd.read_csv("transactions.csv")
    contracts = json.load(open("contracts.json", encoding="utf-8"))
    det = EIP7702Detector(txs, contracts)

    eoa_hits = set(det.detect_eoa_targeted())
    ca_hits, comp_hits = set(), set()
    for _, c1, c2 in det.detect_ca_targeted():
        ca_hits.update([c1, c2])
    for _, _, c1, c2, _ in det.detect_composite():
        comp_hits.update([c1, c2])

    att = txs[(txs["type"] == "Attach") & (txs["to_addr"] != ZERO)]
    creates = txs[txs["type"] == "Create"]
    delegates = sorted(a for a, c in contracts.items() if c.get("is_delegate"))

    rows = []
    for d in delegates:
        beh = behaviour_features(att, creates, d)
        score, pts, why = score_delegate(contracts[d], beh, d in eoa_hits, d in ca_hits, d in comp_hits)
        rows.append({
            "delegate": d, "score": score, "tier": tier_of(score),
            "labeled": contracts[d].get("labeled", False),
            "is_malicious": contracts[d].get("is_malicious", False),
            **beh, "components": pts, "explain": why,
        })
    rows.sort(key=lambda r: r["score"], reverse=True)

    json.dump(rows, open("risk_scores.json", "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    flat = pd.DataFrame(rows).drop(columns=["components", "explain"])
    flat.to_csv("risk_scores.csv", index=False)

    # Mức phơi nhiễm của từng EOA = điểm cao nhất trong các delegate nó đã attach
    sc = {r["delegate"]: r["score"] for r in rows}
    exp = att.assign(delegate_score=att["to_addr"].map(sc)).dropna(subset=["delegate_score"])
    exp = (exp.groupby("from_addr")["delegate_score"].max().rename("max_delegate_score")
              .reset_index().sort_values("max_delegate_score", ascending=False))
    exp["tier"] = exp["max_delegate_score"].map(tier_of)
    exp.to_csv("eoa_exposure.csv", index=False)

    # In kết quả
    print(f"{'delegate':44} {'score':>5} {'tier':6} {'label':9} victims sponsors")
    for r in rows:
        lab = "MAL" if r["is_malicious"] else ("benign" if r["labeled"] else "unlabeled")
        print(f"{r['delegate']:44} {r['score']:5.1f} {r['tier']:6} {lab:9} {r['n_victims']:7} {r['n_sponsors']:8}")
        for w in r["explain"]:
            print("      ", w)

    lab = [r for r in rows if r["labeled"]]
    pos = [r["score"] for r in lab if r["is_malicious"]]
    neg = [r["score"] for r in lab if not r["is_malicious"]]
    if pos and neg:
        wins = sum((p > n) + 0.5 * (p == n) for p in pos for n in neg)
        print(f"\nAUC (chỉ để kiểm tra nhanh, {len(pos)} dương / {len(neg)} âm): {wins / (len(pos) * len(neg)):.3f}")
        flagged = [r for r in lab if r["tier"] == "HIGH"]
        tp = sum(r["is_malicious"] for r in flagged)
        print(f"Ngưỡng HIGH (>=50): báo {len(flagged)} | TP={tp} FP={len(flagged) - tp}")


if __name__ == "__main__":
    main()
