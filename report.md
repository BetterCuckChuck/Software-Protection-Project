# Báo cáo Framework Pipeline obf-agent-bench (Tigress vs. REA Agent — Week 2)

> Nguồn: `Experimentation/obf-agent-bench` | 20 chương trình Juliet v1.3 × 4 kịch bản = 80 runs | Ngôn ngữ: Tiếng Việt (thuật ngữ chuyên ngành, từ riêng, tên riêng giữ Tiếng Anh, có giải thích kèm theo).

## 1. Tổng quan framework pipeline

**Mục tiêu:** đo tác động của làm rối mã nguồn (obfuscation) bằng Tigress lên khả năng dịch ngược tự động của agent chạy theo khung **REA (Reverse Engineer Anything)**. Đầu vào là file nhị phân ELF x86-64 đã lột ký hiệu (**stripped ELF**) `./chal`; đầu ra là `./reconstructed.c` phải biên dịch được và tương đương hành vi.

*Giải thích: **REA** — khung dịch ngược có phương pháp (open_binary → overview → decompile → close_binary); **MCP server** — cổng dịch vụ cấp tool REA cho LLM; **Tigress** — công cụ làm rối mã C.*

| Stage | Thành phần (Tiếng Anh giữ nguyên) | Vào / Ra chính |
|---|---|---|
| 0. Cấu hình | `configs/experiment.yaml`, `configs/tigress_recipes.yaml` | Định nghĩa 20 mẫu, S0..S3, pricing, limits |
| 1. Dữ liệu | `dataset/prepare_dataset.py` | Juliet zip → `normalized_src` (20) + `test_vectors` (65/mẫu, ẩn) |
| 2. Build | `builder/build_scenarios.py` | Tigress → `gcc -O2 -s` + `strip` → `build/<S>/<id>/chal` |
| 3. Chạy agent | `runner/orchestrator.py` + REA MCP + Ghidra 12.1.4 | `jail /tmp/run_<uuid>/` → `reconstructed.c` |
| 4. Chấm | `evaluator/io_harness.py` + `evaluator/cost_evaluator.py` | Axis 1 `Pass_IO` + Axis 2 `OCM`/`ECSR` → `REPORT.md` |

*Giải thích: **jail** — thư mục cô lập tạm mỗi run, chỉ chứa `chal`; **OCM (Obfuscation Cost Multiplier)** — hệ số chi phí làm rối; **ECSR (Expected Cost per Successful Reconstruction)** — chi phí mỗi lần phục hồi thành công.*

## 2. Dữ liệu (dataset) và xây dựng binary (builder)

**Dataset:** chọn mẫu xác định với `seed 42`, phân tầng: `CWE190_Integer_Overflow` (9), `CWE191_Integer_Underflow` (6), `CWE197_Numeric_Truncation_Error` (3), `CWE369_Divide_by_Zero` (2). Điều kiện: file `_01.c`, đọc stdin qua `fscanf`, kiểu `char/int/short/int64_t/unsigned int`, không dùng `rand/malloc/socket/system`, chỉ dùng hàm in `printLine...`. Chuẩn hóa về **single-TU (single translation unit — 1 file C duy nhất tự chứa)** gồm header + hàm in + `main(argv)` gọi `good()/bad()`.

*Giải thích: **single-TU** — gộp toàn bộ chương trình thành 1 file để Tigress biến đổi đồng nhất; **seed** — hạt giống随机 đảm bảo chọn mẫu lặp lại được.*

**Test vectors:** mỗi mẫu sinh 65 vectors ẩn (không đưa vào jail): 15 **curated (ca biên thủ công: 0, ±1, lo/hi, isqrt...)** + 50 **fuzz (sinh ngẫu nhiên + rác để differential-test)**. Định dạng `{id, argv, stdin_hex}`.

*Giải thích: **curated** — ca kiểm thử biên chọn tay; **fuzz** — ca sinh tự động để so sánh vi sai; **differential-test** — chạy 2 binary trên cùng input rồi so sánh.*

| Scenario | Recipe Tigress | Tác động dịch ngược | `.text` / lệnh |
|---|---|---|---|
| `S0_Baseline` | `baseline []` | Đối chứng strip `-O2` | 678 B / 168 |
| `S1_Flatten` | `Flatten` (switch dispatcher) | Phá cấu trúc khối → switch-state + indirect jump | 887 B / 213 (1.31×) |
| `S2_EncodeData` | `InitOpaque` + `EncodeArithmetic` (MBA) + `EncodeLiterals` | Số học/compare → biểu thức MBA + literal tính runtime | 1.683 B / 373 (2.48×) |
| `S3_Combined` | `InitOpaque` + `Flatten` + `MBA` + `Literals` | Dispatcher mà guard/transition cũng bị MBA hóa | 1.798 B / 407 (2.65×) |

Build dùng chung `gcc -O2 -fno-stack-protector -s` + `strip`, đo `binary_stats` (`readelf`/`objdump`) và validate ngữ nghĩa 65 vectors so với S0. Kết quả: 80/80 `valid`.

*Giải thích: **Flatten** — làm phẳng luồng điều khiển; **MBA (Mixed Boolean-Arithmetic)** — mã hóa số học trộn logic-số học; **dispatcher** — vòng switch điều hướng state; **strip** — lột ký hiệu khỏi binary.*

## 3. Chạy agent REA trong jail (runner)

**Vòng đời REA** (trong `runner/prompts/rea_task.md`): (1) `open_binary` — gắn `./chal`; (2) `binary_overview` — image base, `.text`/`.rodata`; (3) `list_procedures` + `list_strings`/`search_strings`, trace `entry` → `__libc_start_main` → `main`; (4) `procedure_pseudo_code` / `procedure_assembly` + `callees`/`callers`/`xrefs` (cấm decompile `_start`, `__libc_csu_init`); (5) deobfuscation: Flatten → `if`/`while`, MBA → `+ - * / %`; (6) `close_binary` → ghi `./reconstructed.c` (C11, chỉ `gcc` test-compile, cấm web).

*Giải thích: **procedure_pseudo_code** — giả mã C của hàm; **xrefs** — tham chiếu chéo địa chỉ; **deobfuscation** — gỡ làm rối.*

**Cơ chế an toàn:** `orchestrator.py` tạo jail mới `/tmp/run_<uuid>/` chỉ chứa `chal`, cấu hình `agy` (model `gemini-3.8-flash`), `hook_guard.py` (**PreToolUse — móc kiểm tra trước mỗi tool**: allow REA/hợp lệ, deny `search_web`, `objdump`/`readelf`/`strings`/`gdb`, `..`, `/home`, `env`), **LimitWatcher (giám sát giới hạn turns/MCP/timeout, `--unlimited` khi cần)** và thu **telemetry (nhật ký token/tool/thời gian)**.

*Giải thích: **jail** — phòng cách ly; **hook_guard** — bảo vệ sandbox; **telemetry** — đo token, MCP calls, wall-time, hook_audit, chal probes.*

Bảng chi phí trung bình / run (thay cho chart Cost S0→S3):

| Metric | S0 | S1 | S2 | S3 |
|---|---|---|---|---|
| Avg cost | $0.0889 | $0.1142 | $0.1249 | $0.1466 |
| Suite cost (n=20) | $1.7784 | $2.2844 | $2.4978 | $2.9318 |
| OCM cost | 1.00× | 1.28× | 1.40× | 1.65× |

## 4. Chấm 2 trục và kết quả 80 runs (evaluator)

**Axis 1 — I/O (`io_harness.py`):** Gate 1 (sanitize + compile): bỏ comment/string rồi regex cấm `system`/`popen`/`__asm__`/`chal`-literal + `gcc -O2 -Wall` biên dịch. Gate 2: 15 curated boundary. Gate 3: 50 fuzz. `Pass_IO = Gate1 && 65/65` khớp (`returncode`/`stdout`/`stderr`, timeout 2000ms).

*Giải thích: **Gate** — cửa kiểm tra; **sanitize** — lọc mã độc/lách luật; **Pass_IO** — đạt tương đương I/O.*

**Axis 2 — Cost (`cost_evaluator.py`):** giá token: `input_uncached` $0.15/1M, `input_cached` $0.0375/1M, `reasoning+output` $0.60/1M. `OCM = avg[Sc]/avg[S0]`; `ECSR = tổng chi phí / số pass`. Ra `benchmark_summary.json`, `summary_table.md`, `simulator.html`.

Bảng tokens / cache (thay cho chart Tokens/cache_hit):

| Metric | S0 | S1 | S2 | S3 |
|---|---|---|---|---|
| Mean tokens | 1.764.585 | 2.313.683 | 2.557.690 | 3.029.830 |
| Cache hit | 93.0% | 94.0% | 94.2% | 94.7% |
| Thinking median | 13.406 | 17.078 | 18.812 | 24.582 |
| Turns mean | 39.8 | 45.8 | 46.9 | 50.9 |
| MCP err | 4.7% | 4.1% | 3.8% | 7.0% |

**Kết quả chính:** 80/80 hoàn tất, 78/80 `Pass_IO` (97.5%), 193.3M tokens, $9.4923, 2.244 MCP calls (2.133 ok/111 err), 6.76h. 2 fail là safety-filter FP ở Turn-1 (`mcp=0`), không phải do obfuscation. 77/78 active vượt `max_turns=25` → bắt buộc `--unlimited`.

*Giải thích: **cache_hit** — tỉ lệ cache prefix; **reasoning tokens** — token suy luận; **Turn-1 safety-filter FP** — bộ lọc an toàn chặn nhầm ngay turn đầu.*

## 5. Giải thích, khuyến nghị và bảng thuật ngữ

**Vì sao:** Dollar tăng chậm hơn token vì 93–94.7% input là prefix-cache rẻ ($0.0375). S3 đắt nhất: thinking median 13.4k→24.6k (1.85×), probes pre-write 2.5→5.6, MCP err 7.0% (`search_procedures` sai query 42%). Có nghịch lý: 7/18 mẫu S1 rẻ hơn S0 do S0 phí turns vào `xrefs`/`search_web`.

**5 khuyến nghị:** 1) Chặn `search_web` trong `hook_guard`; 2) retry Turn-1 safety-filter; 3) sửa false-positive `/*` trong `hook_guard` (`SKIP_KEYS`); 4) log/hạn chế `./chal` probes nếu muốn đo static thuần; 5) báo cáo median/matched OCM thay vì mean thô.

### Phụ lục A. Bảng thuật ngữ Anh–Việt

| Thuật ngữ (EN) | Nghĩa Tiếng Việt | Gặp ở |
|---|---|---|
| REA | Khung dịch ngược có phương pháp | `runner/prompts/rea_task.md` |
| MCP server | Cổng dịch vụ cấp tool cho LLM (ở đây là rea + Ghidra 12.1.4) | `orchestrator.py` |
| Tigress / recipe | Công cụ làm rối C / mẫu lệnh S0..S3 | `tigress_recipes.yaml` |
| Flatten / dispatcher | Làm phẳng luồng điều khiển / vòng switch điều hướng | S1, S3 |
| MBA / EncodeArithmetic | Mã hóa số học trộn logic-số học | S2, S3 |
| stripped ELF / .text | Binary lột ký hiệu / đoạn mã lệnh | `build/.../chal` |
| jail | Thư mục cô lập `/tmp/run_<uuid>/` mỗi run | `orchestrator.py` |
| hook_guard / PreToolUse | Móc chặn tool trước khi chạy để giữ sandbox | `runner/hook_guard.py` |
| Pass_IO / Gate1-3 | Đạt tương đương I/O / 3 cửa: compile + 15 curated + 50 fuzz | `io_harness.py` |
| OCM / ECSR | Hệ số chi phí làm rối / Chi phí mỗi lần phục hồi thành công | `cost_evaluator.py` |
| cache_hit / reasoning | Tỉ lệ cache prefix / token suy luận | `stream_telemetry.py` |

*Nguồn số liệu: `REPORT.md`, `results/summary_table.md`, `docs/TEST_SCENARIO.md`, `configs/experiment.yaml`.*
