Để hiện thực hóa trọn vẹn **9 phương pháp đối chứng (Baselines)** phục vụ cho các kịch bản thực nghiệm **E1–E3** và trả lời các câu hỏi nghiên cứu **RQ1–RQ3**, bạn có thể tận dụng trực tiếp danh mục bài báo và hồ sơ đề tài hiện có trong notebook. 

Dưới đây là bản đồ chi tiết từng Baseline tương ứng với **Paper/Tài liệu tham chiếu chính**, **Cơ chế kỹ thuật cần trích xuất**, và **Cách chuyển đổi thích ứng (Adaptation) sang tầng mã nguồn C**:

---

### 1. Original (Mẫu gốc đối chứng)
* **Tài liệu căn cứ:** `thesis-proposal.md` (Mục *Bộ dữ liệu thực nghiệm* & *Dataset*).
* **Bản chất kỹ thuật:** 
  * Đây là tập 20–30 chương trình C gốc (.c) chưa qua bất kỳ thao tác biến đổi nào.
  * Được biên dịch bằng cấu hình compiler cố định (MSVC/GCC).
* **Vai trò:** Cung cấp mốc đo lường ban đầu (Ground Truth baseline) về tỷ lệ bị phát hiện của detector gốc trước khi tiến hành tấn công.

---

### 2. Random (Random Search)
* **Tài liệu tham chiếu:** 
  * `TransForge.pdf` (Section 3.6 & Table 13: đối chứng với Random Search).
  * `GAMMA.pdf` (Section III & V: đối chứng với random perturbation).
  * `AOP-Mal.pdf` (Section 3.1 & Figure 3: phân tích hạn chế của random action).
* **Bản chất kỹ thuật:**
  * Chọn ngẫu nhiên đồng đều (Uniform Random) một số lượng toán tử \\(k\\) từ thư viện biến đổi mã C (*Common C Action Pool*).
  * Không sử dụng hàm fitness, không có bộ nhớ, không cập nhật xác suất.
* **Ràng buộc:** Chạy lặp lại với cùng giới hạn số lượt truy vấn detector (*Detector Query Budget*) như các phương pháp khác.

---

### 3. Heuristic (Biến đổi quy tắc cấu trúc cố định)
* **Tài liệu tham chiếu:**
  * `Next-Gen Metamorphism.pdf` (Section 4 & Table 2: các kỹ thuật của Metamorphic Engine như *MetaME*).
  * `TransForge.pdf` (Section 2: phân tích các công cụ obfuscation định mẫu cố định như *Veil, TheFatRat, MsfVenom*).
* **Bản chất kỹ thuật:**
  * Áp dụng một chuỗi quy tắc biến đổi tĩnh theo thứ tự cố định, mang tính tiền định (deterministic rules):
    * Làm phẳng luồng điều khiển (*Control Flow Flattening*).
    * Chèn mã rác / hàm rác (*Dead Code Insertion*).
    * Đổi tên biến / hàm ngẫu nhiên (*Identifier Renaming*).
    * Mã hóa chuỗi / hằng số (*String/Constant Obfuscation*).
* **Vai trò:** Đại diện cho các công cụ obfuscation/metamorphic truyền thống không có cơ chế tìm kiếm thích nghi theo phản hồi của detector.

---

### 4. GA-only (Thuật toán Di truyền thuần túy)
* **Tài liệu tham chiếu chính:** **`TransForge.pdf`** (Section 3: *Genetic Algorithm Framework*).
* **Tài liệu bổ trợ:** `AOP-Mal.pdf` (Algorithm 1, 2, 3: các toán tử Tournament, Crossover, Mutation).
* **Bản chất kỹ thuật & Cách triển khai:**
  * **Chromosome:** Mã hóa chuỗi toán tử biến đổi mã C thành vectơ gene.
  * **Toán tử di truyền:** *Tournament Selection* (kích thước \\(k=3\\)), *Uniform Crossover*, và *Stochastic Mutation*.
  * **Hàm Fitness:** Cài đặt hàm thích nghi kết hợp đơn mục tiêu (Weighted Composite Fitness) như công thức của TransForge:
    \\[F = w_s \cdot S + w_b \cdot B + w_f \cdot C + w_e \cdot E\\]
    *(Trong đó \\(S\\) là điểm né tránh tĩnh, \\(B\\) là né tránh hành vi, \\(C\\) là điểm kiểm chứng tính đúng qua C1, \\(E\\) là hệ số phạt độ phình dung lượng)*.
* **Lưu ý:** Chạy hoàn toàn bằng GA, không có sự tham gia của LLM.

---

### 5. Bandit (Multi-Armed Bandit thích nghi không dùng LLM)
* **Tài liệu tham chiếu chính:** **`Mab-Malware.pdf`** (Section 4: *MAB-Malware Framework*, Algorithm 1 & 2).
* **Bản chất kỹ thuật & Cách chuyển đổi (Adaptation):**
  * **Mô hình hóa không trạng thái (Stateless):** Mỗi toán tử biến đổi mã C cụ thể được coi là một máy đánh bạc (*Slot Machine* \\(m_i\\)).
  * **Phân phối Beta & Thompson Sampling:** Mỗi machine duy trì tham số \\(\text{Beta}(\alpha_i, \beta_i)\\). Lấy mẫu từ phân phối Beta để chọn toán tử tiếp theo.
  * **Cập nhật Reward:** Nếu biến thể C qua được detector, tăng \\(\alpha_i \leftarrow \alpha_i + 1\\); nếu bị bắt hoặc lỗi, tăng \\(\beta_i \leftarrow \beta_i + 1\\).
  * **Action Minimizer:** Rút gọn chuỗi biến đổi mã C sau khi né tránh thành công để tìm ra vi toán tử (*micro-actions*) cốt lõi gây ra né tránh.

---

### 6. Single-Agent (LLM Agent đơn lẻ có bộ nhớ phản hồi)
* **Tài liệu tham chiếu chính:** **`Reflexion.pdf`** (Section 2 & 3: *Verbal Reinforcement Learning & Self-Reflection Loop*).
* **Tài liệu bổ trợ về Prompting C:** `Next-Gen Metamorphism.pdf` (Section 4.4: *Transformation Prompts at Source-level*).
* **Bản chất kỹ thuật & Cách triển khai:**
  * **Kiến trúc:** 1 LLM Agent đóng vai trò vừa là *Actor* (sinh mã biến đổi) vừa là *Self-Reflector* (tự suy ngẫm lỗi).
  * **Bộ nhớ Episodic Memory:** Khi biến thể C bị detector phát hiện hoặc lỗi biên dịch/runtime crash (từ C1), kết quả phản hồi nhị phân hoặc log lỗi được chuyển thành văn bản suy ngẫm (*Self-Reflection text*) lưu vào bộ nhớ đệm (buffer 3–5 lượt).
  * **Vòng lặp:** Agent đọc lại các phản hồi thất bại trước đó trong prompt để tự điều chỉnh việc biến đổi code C ở lượt kế tiếp.

---

### 7. Multi-Agent (Hệ thống Đa Agent phân vai thuần túy)
* **Tài liệu căn cứ:** `thesis-proposal.md` (Mục *RQ2*, *E3: Ablation Study* & *Phương pháp đối chứng*).
* **Bản chất kỹ thuật & Cách triển khai:**
  * **Cấu trúc phân vai (Role-playing Prompts):** Phân chia công việc thành các Agent chuyên biệt tương tác tuần hoàn:
    1. *Planner/Analysis Agent:* Đọc log detector và cấu trúc code C để hoạch định chiến lược (ví dụ: cần ẩn API này, cần làm rối luồng hàm kia).
    2. *Coder/Mutator Agent:* Trực tiếp nhận chỉ thị và viết lại các khối mã nguồn C.
    3. *Reviewer/Validator Agent:* Đọc kết quả từ giao thức C1 để đánh giá xem code có vi phạm ngữ nghĩa hay dễ bị lỗi biên dịch không trước khi gửi đi.
  * **Đặc điểm:** Hoạt động hoàn toàn dựa trên sự trao đổi message giữa các Agent LLM, **không tích hợp thuật toán tiến hóa (NSGA-II)**.

---

### 8. Hybrid cố định (LLM + GA theo tỷ lệ tĩnh)
* **Tài liệu tham chiếu:** 
  * `thesis-proposal.md` (Mục *Khoảng trống RG2* & *Baseline 8*).
  * `EoH.pdf` (Section 3: *Evolution of Heuristics Framework*).
* **Bản chất kỹ thuật & Cách triển khai:**
  * Kết hợp LLM và GA nhưng theo cơ chế **luân phiên cứng (hardcoded schedule)**:
    * Ví dụ: Cứ sau mỗi thế hệ GA (hoặc cố định 20% cá thể trong quần thể), hệ thống tự động gọi LLM Agent để đột biến hoặc sinh toán tử mới.
  * **Điểm yếu (cần bộc lộ trong thực nghiệm):** Không có cơ chế giám sát độ đình trệ (*stagnation*) hay ngân sách. LLM vẫn bị gọi định kỳ gây lãng phí Token ngay cả khi GA đang tiến triển tốt.

---

### 9. Proposed (Mô hình Đề xuất - C2 Coordinator + NSGA-II + Reflexion)
* **Tài liệu tham chiếu kết hợp:**
  * **Cốt lõi Đa mục tiêu:** **`NSGA-II.pdf`** (Section III: *Fast Non-dominated Sorting, Crowding Distance, và Constraint-handling*).
  * **Khung Tiến hóa Heuristic:** **`EoH.pdf`** (Cơ chế tiến hóa đồng thời ý tưởng (*thoughts*) và mã (*code*)).
  * **Bộ nhớ phản hồi khi bị kẹt:** **`Reflexion.pdf`** (Cơ chế verbal memory khi kích hoạt LLM).
  * **Kiểm chứng chức năng:** **`thesis-proposal.md`** & **`Alive-2.pdf`** (Giao thức C1 phân loại 3 trạng thái: *Build Fail, Passed Test, Undetermined*).
* **Bản chất kỹ thuật:**
  * Bình thường hệ thống ưu tiên chạy **NSGA-II** để tối ưu đa mục tiêu (Evasion Rate vs. Resource Budget) với chi phí thấp.
  * **Bộ điều phối thích nghi có tính phí (C2):** Giám sát liên tục chất lượng quần thể. **Chỉ khi NSGA-II bị rơi vào cực trị cục bộ** (không cải thiện Pareto Front sau \\(K\\) thế hệ) hoặc gặp tỷ lệ lỗi cao, C2 mới kích hoạt **LLM Agent (Reflexion)** để suy luận ngữ nghĩa mã C và sinh toán tử mới giúp thoát kẹt.

---

###  Bảng Tổng hợp Ánh xạ Baseline & Resource

| STT | Tên Baseline | Tài liệu / Paper tham chiếu chính | Module / Thuật toán cốt lõi cần cài đặt |
| :---: | :--- | :--- | :--- |
| **1** | **Original** | `thesis-proposal.md` | Compiler MSVC/GCC pipeline (Unmodified C code). |
| **2** | **Random** | `TransForge.pdf`, `GAMMA.pdf` | Uniform Random Operator Selection. |
| **3** | **Heuristic** | `Next-Gen Metamorphism.pdf` | Rule-based Obfuscation Chain (Flattening, Dead code, Rename). |
| **4** | **GA-only** | `TransForge.pdf` | Single-objective Genetic Algorithm (Tournament, Crossover, Mutate). |
| **5** | **Bandit** | `Mab-Malware.pdf` | Multi-Armed Bandit, Thompson Sampling, Beta distributions, Minimizer. |
| **6** | **Single-Agent** | `Reflexion.pdf` | LLM Actor + Verbal Self-reflection buffer (Episodic Memory). |
| **7** | **Multi-Agent** | `thesis-proposal.md` | Multi-role Collaboration Prompts (Planner, Coder, Reviewer). |
| **8** | **Hybrid cố định** | `EoH.pdf`, `thesis-proposal.md` | Fixed Schedule Integration (Fixed % LLM calls per GA generation). |
| **9** | **Proposed** | `NSGA-II.pdf`, `Reflexion.pdf`, `thesis-proposal.md` | NSGA-II Pareto Front + Cost-Aware Adaptive Coordinator (C2). |

---

Bạn có muốn chúng ta đi sâu vào thiết kế chi tiết mã giả (pseudocode) hoặc cấu trúc thư mục code Python để tổ chức khung chạy 9 baseline này không?