# EIP-7702 Malicious Contract Detection

## Các tệp chính
- `fetch_txs.py`: Thu thập giao dịch EIP-7702 on-chain qua RPC.
- `build_contracts.py`: Tải bytecode, trích xuất đặc trưng và đối chiếu nhãn.
- `detector.py`: Cài đặt quy tắc phát hiện EOA-targeted, CA-targeted, Composite.
- `evaluate_labeled.py`: Đánh giá Precision, Recall, F1 trên tập dữ liệu có nhãn.
- `transactions.csv`, `contracts.json`, `no_code_delegates.json`: Dữ liệu thu thập (Ethereum block 22,500,001 – 22,501,000).
- `ket_qua.json`: Kết quả phát hiện và chỉ số đánh giá (`TP=2, FP=5, FN=0, TN=0, Precision=0.2857, Recall=1.0, F1=0.4444`).

## Cách chạy
```bash
pip install -r requirements.txt
python evaluate_labeled.py
