# Project Sentinel — Báo cáo Tuần 2

Repo nộp bài Tuần 2 (VinUni × VinSOC), tách riêng từ đồ án Sentinel gốc. Đây là
bước tiếp theo sau Tuần 1: lấy chính các artifact quét đã che secret của Tuần 1,
chuẩn hóa về một cấu trúc chung có nguồn gốc kiểm chứng được, và dựng một kho tri
thức OWASP/tool để tìm kiếm **offline** (không gọi mạng, không gọi LLM).

## 1. Mục tiêu Tuần 2 em đã làm

Theo yêu cầu đồ án, Tuần 2 có hai phần: (a) gộp kết quả quét của Tuần 1 thành một
định dạng thống nhất, và (b) dựng kho tri thức bảo mật tra cứu được, có ví dụ cho
SQL Injection và XSS. Em làm đúng hai phần đó, và giữ nguyên nguyên tắc an toàn từ
Tuần 1 — chỉ đọc bản đã che secret, che thêm một lần nữa khi ghi ra, và không đưa
secret/raw report vào gói bàn giao.

Điểm em cố ý giữ kỷ luật: adapter Tuần 2 **tách riêng** khỏi normalizer Charter của
đồ án lớn. Nó chỉ nhận đúng ba file đã nộp của Tuần 1, không nới lỏng đường dẫn
Charter/CI để "cho tiện".

## 2. Kiến trúc

```
Artifact đã sanitize của Tuần 1
  ├── nuclei.san.jsonl (21)  ─┐
  ├── trivy.san.json   (4)   ─┼─► normalize_week1_artifacts.py ─► week1.aggregate.jsonl (36 bản ghi)
  └── semgrep.san.json (11)  ─┘     (che lại + provenance SHA-256)  + week1.aggregate.manifest.json

Kho tri thức (tra cứu offline)
  ├── charter-corpus-manifest.json (13 doc: 10 OWASP + 3 tool)  ─┐
  └── charter-examples/*.json      (12 ví dụ: SQLi, XSS, ...)   ─┴─► search-knowledge.py "SQL Injection" ─► content + source + sha256
```

- **Chỉ đọc bản đã che của Tuần 1**: input là `scanners/out/*.san.*` — đúng baseline
  đã nộp (21 Nuclei, 4 Trivy, 11 Semgrep). Adapter băm SHA-256 từng file nguồn và
  ghi vào manifest, nên ai cũng đối chiếu lại được số lượng/digest.
- **Che một lần nữa khi ghi ra**: URL, host và đường dẫn tuyệt đối trong trường tự
  do bị redact khỏi output; locator có cấu trúc mà không an toàn thì bị từ chối hoặc
  đổi thành định danh opaque. Không có secret nào chạm tới file aggregate.
- **Không ghi đè**: adapter từ chối nếu output đã tồn tại, từ chối symlink/FIFO và
  input không hợp lệ — tránh vô tình ghi nhầm hay bị dẫn đường qua file lạ.

## 3. Kết quả chuẩn hóa (aggregate)

Adapter đọc ba file baseline và xuất **36 bản ghi JSONL** theo schema
`week1-submission/v1`, không nhập nhèm số lượng giữa các công cụ:

| Công cụ | Loại | Baseline Tuần 1 | Vào (input) | Nhận (admitted) | Từ chối |
|---|---|---|---|---|---|
| Nuclei | DAST | 21 | 21 | 21 | 0 |
| Trivy | secret scan | 4 | 4 | 4 | 0 |
| Semgrep | SAST | 11 | 11 | 11 | 0 |

**Tổng: 36 bản ghi**, khớp đúng tổng 36 cảnh báo của Tuần 1. Mỗi bản ghi giữ
`finding_id`/`source_id` truy ngược được về file gốc + digest, ví dụ:

```json
{
  "schema_version": "week1-submission/v1",
  "tool": "nuclei", "scanner": "DAST",
  "title": "Public Swagger API - Detect", "severity": "Info",
  "location": "path:/api-docs/swagger.json",
  "source_id": "week1-submission:nuclei:sha256:749fcb54...:item:1"
}
```

Kết quả nằm ở `artifacts/week1.aggregate.jsonl` (36 dòng) và
`artifacts/week1.aggregate.manifest.json` (số lượng + SHA-256 từng nguồn).

## 4. Kho tri thức và tìm kiếm offline

Corpus gồm **13 tài liệu** (đủ 10 mục OWASP Top 10 2021 + tài liệu 3 tool
Nuclei/Trivy/Semgrep) và **12 ví dụ** web, trong đó có 4 ví dụ SQL Injection và 4
ví dụ XSS. Mỗi document/ví dụ đều có `source`, `source_ref` (bắt buộc HTTPS) và
`sha256` của nội dung — `search-knowledge.py` xác thực lại digest, coverage và
đường dẫn ví dụ trước khi trả kết quả, nên corpus không thể bị sửa lén mà vẫn qua.

Tìm `SQL Injection` và `XSS` đều trả về nội dung, nguồn và SHA-256 liên quan:

```bash
.venv/bin/python scripts/search-knowledge.py "SQL Injection" -k 3
.venv/bin/python scripts/search-knowledge.py XSS -k 3
```

Ví dụ `"SQL Injection"` trả về `owasp-a03` (mục Injection) và các ví dụ SQLi, kèm
`source_ref` OWASP và `sha256` để kiểm chứng — không bịa nguồn, không sinh văn bản
mới. Đây là tra cứu từ khóa offline trên corpus đã cam kết, **không** phải RAG/LLM
chạy live.

## 5. Cách chạy lại (đã tự kiểm tra từng bước)

Yêu cầu: Python 3.11+.

```bash
# 1. Tạo venv và cài dependency đã ghim hash (khớp chính xác requirements.lock)
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock

# 2. Chạy toàn bộ kiểm chứng bằng một lệnh
PYTHON=.venv/bin/python bash scripts/run-week2-checks.sh

# 3. (tuỳ chọn) Tìm thủ công trong kho tri thức
.venv/bin/python scripts/search-knowledge.py "SQL Injection" -k 3
.venv/bin/python scripts/search-knowledge.py XSS -k 3
```

Kỳ vọng ở bước 2:

```text
Week 2 checks: PASS
```

Em đã tự chạy lại trước khi nộp: `run-week2-checks.sh` chạy trọn 10 test (aggregate,
provenance, corpus/search, mutation và các biên an toàn) và in `Week 2 checks: PASS`;
hai lệnh tìm ở bước 3 trả kết quả có `source_ref` + `sha256` như mô tả ở mục 4. Cài
bằng `pip --require-hashes` nên nếu một dependency lệch hash, bước 1 sẽ dừng ngay —
đây là chủ đích để môi trường chạy lại đúng bằng môi trường em đã kiểm.

## 6. Cấu trúc gói bàn giao

- `agent/normalize_week1_artifacts.py`: adapter tương thích + schema chung Tuần 2
  (`week1-submission/v1`); `agent/pii.py` giữ phần che dữ liệu nhạy cảm.
- `scanners/out/`: **chỉ** artifact đã sanitize/baseline của Tuần 1 (input).
- `artifacts/`: output aggregate (`.jsonl`) + manifest số lượng/digest.
- `rag/`: `charter-corpus-manifest.json` và `charter-examples/*.json`.
- `scripts/run-week2-checks.sh`: chạy toàn bộ kiểm chứng bằng một lệnh.
- `scripts/search-knowledge.py`: tìm kiếm offline trên corpus.
- `tests/test-week2-delivery.py`: kiểm aggregate, provenance, corpus/search,
  mutation và các biên an toàn.
- `requirements.lock`: closure dependency có SHA-256, dùng với `pip --require-hashes`.

Gói này **không** chứa secret, raw scan report, cấu hình LLM, hay bất kỳ claim nào
về chạy RAG/LLM live.

## 7. Phạm vi và lựa chọn có chủ đích

Những phần dưới đây là lựa chọn phạm vi, không phải điều còn thiếu so với yêu cầu
Tuần 2:

- **Adapter tách riêng khỏi Charter**: `normalize_week1_artifacts.py` cố ý không
  dùng chung đường Charter (controller, recon, reporting, proposal). Nó chỉ là lớp
  tương thích cho đúng artifact đã nộp của Tuần 1 — em không nới lỏng normalizer
  dùng chung của đồ án lớn chỉ để gộp cho nhanh.
- **Tra cứu offline, không phải RAG/LLM live**: yêu cầu Tuần 2 cần kho tri thức tìm
  được với ví dụ SQLi/XSS. Em làm tìm kiếm từ khóa offline trên corpus đã cam kết +
  xác thực digest, thay vì dựng vector DB hay gọi model — vừa đủ yêu cầu, vừa chạy
  lại được deterministic, không phụ thuộc mạng hay key.
- **Giữ nguyên baseline 36 của Tuần 1**: aggregate bám đúng ba file đã nộp (21/4/11)
  để số liệu truy ngược được, không trộn thêm kết quả quét mới (vốn trôi theo thời
  điểm quét như đã nêu ở báo cáo Tuần 1).

Đây là bằng chứng phạm vi Tuần 2, không phải báo cáo hoàn tất toàn bộ chương trình
sáu tuần.
