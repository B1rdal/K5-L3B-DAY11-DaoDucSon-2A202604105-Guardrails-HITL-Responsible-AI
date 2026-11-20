# K5 — Day 11: Guardrails, HITL & Responsible AI

- **Họ tên:** Dao Duc Son
- **MSSV:** 2A202604105
- **Lớp:** K5-L3B

## Cài đặt

Python 3.11 hoặc 3.12 được khuyến nghị.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Điền API key vào `.env`. File này được loại khỏi Git.

| Agent | Provider | Model |
|---|---|---|
| Blue (mặc định) | OpenRouter | `liquid/lfm-3-1.7b:free` |
| Blue (thay thế) | DeepSeek | `DEEPSEEK_MODEL`, mặc định `deepseek-flash` |
| Blue (thay thế) | Gemini | `GEMINI_MODEL`, mặc định `gemini-3.5-flash` |
| Red / Red Advance | OpenAI hoặc Gemini | `gpt-4o-mini` hoặc `gemini-3.5-flash` |
| Red / Red Advance (thay thế) | DeepSeek | `DEEPSEEK_MODEL`, mặc định `deepseek-flash` |

DeepSeek dùng `DEEPSEEK_API_KEY` và `DEEPSEEK_MODEL`. Chọn DeepSeek cho Red bằng `RED_TEAM_PROVIDER=deepseek`, cho Blue bằng `--blue-provider deepseek`. Mặc định Blue vẫn dùng OpenRouter. Rubric chỉ định OpenRouter cho Blue và OpenAI/Gemini cho Red; artifact ghi provider, model thực tế và trạng thái khớp cấu hình rubric.

## Thiết kế

Luồng Blue: rate limit theo user → lọc input → model → lọc output. Input được chuẩn hóa Unicode, phát hiện prompt injection và giới hạn chủ đề ngân hàng. Output che thông tin cá nhân và secret, kể cả các dạng mã hóa phổ biến của secret demo.

Audit và monitoring là observer bên ngoài plugin: ghi nhận kết quả, lớp chặn và độ trễ của từng request. Audit che dữ liệu nhạy cảm trước khi lưu. Egress chỉ chấp nhận HTTPS trên `api.vinbank.example` hoặc `cases.vinbank.example`, đồng thời chặn payload chứa secret hoặc thông tin cá nhân. Policy yêu cầu phê duyệt con người cho thao tác rủi ro nằm trong `src/agents/security_boundary.py`.

Red là mục tiêu phòng thủ yếu. Red Advance sử dụng regex và NVIDIA NeMo Guardrails, gồm input rails và output rails. Năm prompt tấn công kiểm tra completion, dịch/định dạng, giả định, xác nhận và leo thang nhiều bước.

## Chạy lab

Chạy từ thư mục gốc repository:

```powershell
python src/main.py --part 2
python src/main.py --part 3
python src/main.py --part 4
python -m pytest tests/smoke tests/public tests/regression -q
python scripts/grade.py --submission-dir . --out outputs/grade_report.json
```

Chạy Blue bằng DeepSeek:

```powershell
python src/main.py --part 3 --blue-provider deepseek
```

Chạy Blue bằng Gemini, sử dụng `GOOGLE_API_KEY` (hoặc `GEMINI_API_KEY`) và `GEMINI_MODEL` trong `.env`:

```powershell
python src/main.py --part 3 --blue-provider gemini
```

Gemini Blue sử dụng [endpoint tương thích OpenAI của Google](https://ai.google.dev/gemini-api/docs/openai) để giữ nguyên các plugin phòng thủ. Model Blue được rubric chỉ định vẫn là OpenRouter Liquid.

Checkpoint 2 và bộ test không cần key thật. Checkpoint 3 cần key của provider Blue được chọn; Checkpoint 4 cần key của provider Red được chọn. Kết quả được sinh bằng các lệnh chạy:

| Checkpoint | Artifact |
|---|---|
| 3 | `outputs/results.json`, `outputs/audit_log.json`, `outputs/metrics.json` |
| 4 | `outputs/attack_results.json`, `outputs/unsafe_attack_result.json`, `outputs/guards_attack_result.json` |
| 5 | `outputs/grade_report.json`, `outputs/lab_report.md` |

Bộ phòng thủ gồm 5 câu banking an toàn, 8 câu tấn công, 3 case biên, kiểm tra egress và burst 15 request trên rate limiter giới hạn 10 request/60 giây. Burst kiểm tra trực tiếp callback của rate limiter và không gọi model.

## Tài liệu bài tập

- [Checkpoints](CHECKPOINTS.md)
- [Rubric](RUBRIC.md)
- [Hướng dẫn nộp](SUBMISSION.md)
- [Quy định](RULES.md)
