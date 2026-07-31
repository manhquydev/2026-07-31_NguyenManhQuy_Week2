# Project Sentinel — Tuần 2

Gói bàn giao này chứng minh hai yêu cầu của Tuần 2: chuẩn hóa trực tiếp các
artifact quét đã sanitize của Tuần 1 thành một cấu trúc chung, và tìm kiếm
offline trong kho tri thức OWASP/tool với các ví dụ SQL Injection và XSS.

## Phạm vi đã kiểm chứng

- Đọc đúng ba file baseline của Tuần 1: 21 Nuclei, 4 Trivy và 11 Semgrep.
- Xuất 36 bản ghi JSONL theo schema `week1-submission/v1`, có provenance
  SHA-256 và manifest số lượng/digest.
- Không nới lỏng normalizer Charter/CI của dự án lớn: đây là adapter tương
  thích chỉ cho artifact đã nộp của Tuần 1.
- Kho tri thức gồm OWASP Top 10, tài liệu Nuclei/Trivy và 12 ví dụ web.
- Tìm `SQL Injection` và `XSS` trả nội dung, nguồn và SHA-256 liên quan.

Adapter từ chối symlink/FIFO, input không hợp lệ, URL/host/đường dẫn tuyệt đối
trong trường tự do, và không ghi đè output đã tồn tại.

## Chạy lại

Yêu cầu: Python 3.11+.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
PYTHON=.venv/bin/python bash scripts/run-week2-checks.sh
```

Kỳ vọng:

```text
Week 2 checks: PASS
```

Tìm thủ công:

```bash
.venv/bin/python scripts/search-knowledge.py "SQL Injection" -k 3
.venv/bin/python scripts/search-knowledge.py XSS -k 3
```

## Cấu trúc

- `agent/normalize_week1_artifacts.py`: normalizer tương thích và schema
  chung Tuần 2.
- `scanners/out/`: chỉ các artifact đã sanitize/baseline từ Tuần 1.
- `rag/`: manifest OWASP/tool và 12 ví dụ.
- `scripts/run-week2-checks.sh`: kiểm chứng một lệnh.

Không chứa secrets, raw scan report, cấu hình LLM hay claim về chạy live
RAG/LLM. Đây là bằng chứng phạm vi Tuần 2, không phải báo cáo hoàn tất toàn
bộ chương trình sáu tuần.
