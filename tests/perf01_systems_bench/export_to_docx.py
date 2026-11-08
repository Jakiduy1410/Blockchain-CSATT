"""
Script tu dong chuyen doi BAO_CAO_PERF01.md sang file Microsoft Word (.docx)
chuan hoc thuat, tu dong chen bang bieu dinh dang dep va cac bieu do truc quan hoa.
"""

import sys
from pathlib import Path
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPT_DIR.parent.parent
RESULTS_DIR = BASE_DIR / 'benchmarks' / 'results' / 'perf01_resource_stress'
DOCX_PATH = RESULTS_DIR / 'BAO_CAO_PERF01.docx'

def set_cell_background(cell, fill_hex):
    shading_elm = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    cell._tc.get_or_add_tcPr().append(shading_elm)

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
        node = OxmlElement(f'w:{m}')
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)

def create_report_docx():
    doc = docx.Document()

    # Thiet lap le trang (Normal 1 inch)
    for section in doc.sections:
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)

    # Style mac dinh
    normal_style = doc.styles['Normal']
    normal_style.font.name = 'Times New Roman'
    normal_style.font.size = Pt(12)
    normal_style.font.color.rgb = RGBColor(0x22, 0x22, 0x22)
    normal_style.paragraph_format.line_spacing = 1.15
    normal_style.paragraph_format.space_after = Pt(6)

    # TIEU DE CHINH
    p_title = doc.add_paragraph()
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_title = p_title.add_run("BÁO CÁO THỰC NGHIỆM ĐỒ ÁN MÔN HỌC\nCƠ SỞ AN TOÀN THÔNG TIN")
    r_title.bold = True
    r_title.font.size = Pt(16)
    r_title.font.color.rgb = RGBColor(0x00, 0x33, 0x66)

    p_sub = doc.add_paragraph()
    p_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_sub = p_sub.add_run("PHẦN 2: TƯƠNG THÍCH PHẦN CỨNG & MẠNG\nKỊCH BẢN PERF-01: ĐO LƯỜNG GIỚI HẠN TÀI NGUYÊN NODE TRÊN PHẦN CỨNG YẾU\n(RESOURCE CONSTRAINED STRESS TEST)")
    r_sub.bold = True
    r_sub.font.size = Pt(13)
    r_sub.font.color.rgb = RGBColor(0x8B, 0x00, 0x00)

    # Thong tin chung
    p_info = doc.add_paragraph()
    p_info.alignment = WD_ALIGN_PARAGRAPH.LEFT
    p_info.paragraph_format.space_after = Pt(12)
    r_info = p_info.add_run(
        "• Học phần: Cơ sở An toàn Thông tin / Blockchain Engineering\n"
        "• Hạng mục báo cáo: Kịch bản PERF-01 (Thành viên 4 - Hardware Benchmark & DevOps)\n"
        "• Đối tượng kiểm thử: Chữ ký số Hậu lượng tử NIST FIPS 204 (ML-DSA-44, 65, 87) vs ECDSA (secp256k1)\n"
        "• Môi trường triển khai: Linux Debian 12 Container (Docker, cgroups v2, Open Quantum Safe liboqs C-engine)"
    )
    r_info.font.italic = True
    r_info.font.size = Pt(11)

    doc.add_heading("1. ĐẶT VẤN ĐỀ & MỤC TIÊU CỦA KỊCH BẢN PERF-01", level=1)
    doc.add_paragraph(
        "Trong bối cảnh điện toán lượng tử phát triển nhanh chóng, các thuật toán mật mã khóa công khai truyền thống như RSA và ECDSA (đang được Bitcoin và Ethereum sử dụng) đứng trước nguy cơ bị bẻ gãy hoàn toàn bởi thuật toán Shor. Nhằm đảm bảo an toàn dài hạn, Viện Tiêu chuẩn và Công nghệ Quốc gia Hoa Kỳ (NIST) đã chính thức chuẩn hóa bộ tiêu chuẩn mật mã hậu lượng tử (PQC - Post-Quantum Cryptography), tiêu biểu là thuật toán chữ ký số dựa trên mạng tinh thể ML-DSA (Module-Lattice-Based Digital Signature Algorithm - FIPS 204)."
    )
    doc.add_paragraph(
        "Tuy nhiên, việc nâng cấp chữ ký số từ ECDSA lên ML-DSA kéo theo sự gia tăng đột biến về kích thước dữ liệu:\n"
        "• Chữ ký ECDSA (secp256k1) chỉ có kích thước 64 bytes (khóa công khai 33–65 bytes).\n"
        "• Chữ ký ML-DSA dao động từ 2,420 bytes (ML-DSA-44), 3,309 bytes (ML-DSA-65) đến 4,627 bytes (ML-DSA-87), tức phình to gấp 37 đến 72 lần so với chữ ký truyền thống. Khi đóng gói dưới định dạng JSON và mã hóa chuỗi Hex trong giao thức Blockchain, mỗi giao dịch nạp vào sổ cái chiếm từ 7.7 KB đến 14.7 KB (gấp 15–29 lần so với 499 bytes của ECDSA)."
    )
    doc.add_paragraph(
        "Mục tiêu cốt lõi của kịch bản PERF-01:\n"
        "1. Lượng hóa sự suy hao tài nguyên phần cứng: Đo lường chính xác mức độ chiếm dụng CPU, đỉnh RAM (Peak RAM), thông lượng tiếp nhận giao dịch (Ingestion TPS) trên 3 cấp độ phần cứng đại diện: Server (Cloud/Datacenter), Edge (Gateway/Raspberry Pi 4) và IoT (Thiết bị nhúng/Smart Meter).\n"
        "2. Khảo sát ngưỡng OOM thực nghiệm (Extreme OOM Hunt): Tìm ra ranh giới ngưỡng sập nguồn (Out-Of-Memory Crash) khi node nhúng bị quá tải Mempool bởi các giao dịch PQC cồng kềnh, phân tích cơ chế nhân Linux gửi tín hiệu hủy diệt tiến trình SIGKILL (Exit Code 137).\n"
        "3. Đo lường độ trễ đồng thuận trong mạng lưới Mesh P2P thực tế (Macro-Benchmark): Khảo sát hành vi của một Node bị giới hạn tài nguyên (DUT - Device Under Test) khi hòa mạng cùng cụm 5 Node nền (Background Nodes) giao tiếp qua kênh WebSocket bảo mật TLS 1.3 / ECDHE; bóc tách chính xác tỷ trọng giữa thời gian tính toán của CPU và thời gian trễ của đường truyền mạng."
    )

    doc.add_heading("2. CÀI ĐẶT & THIẾT LẬP MÔI TRƯỜNG THỰC NGHIỆM", level=1)
    doc.add_heading("2.1. Đóng gói Container & Biên dịch Thư viện liboqs C Engine", level=2)
    doc.add_paragraph(
        "Node Blockchain chạy trên nền Python 3.11 Debian Linux Slim. Điểm mấu chốt trong thiết kế môi trường là việc tích hợp thư viện Open Quantum Safe (liboqs):\n"
        "• Thư viện liboqs được biên dịch trực tiếp từ mã nguồn C thông qua CMake và Ninja, kích hoạt tối ưu hóa phần cứng x86_64 (AVX2/SIMD).\n"
        "• Ứng dụng Python giao tiếp với liboqs qua wrapper C-extension liboqs-python. Khi thực hiện thẩm định chữ ký số PQC, Python giải phóng khóa thông dịch toàn cục GIL (Global Interpreter Lock), cho phép các luồng worker HTTP xử lý song song thực sự trên đa nhân CPU.\n"
        "• Ngược lại, thuật toán chuẩn đối chứng ECDSA (secp256k1) sử dụng thư viện python-ecdsa. Đây là thư viện thuần Python (Pure-Python), các vòng lặp toán học đường cong Elliptic bị thông dịch từng dòng bytecode và giữ chặt GIL."
    )

    doc.add_heading("2.2. Định nghĩa 3 Cấu hình Phần cứng Cô lập qua Linux cgroups v2", level=2)
    doc.add_paragraph(
        "Môi trường kiểm thử được chuẩn hóa thành 3 hồ sơ phần cứng (Profiles) thông qua file cấu hình perf/docker-compose.yml. Để đo lường chính xác nguy cơ tràn RAM vật lý, thiết lập quan trọng nhất là vô hiệu hóa triệt để bộ nhớ ảo Swap (--memory-swap bằng đúng --memory, tức Swap = 0), buộc tiến trình phải đối mặt trực diện với bộ cấp phát bộ nhớ của nhân Linux:\n"
        "• Profile 1 – Server (Cloud / Datacenter Node): 4.0 vCPU, 4,096 MB RAM, Swap = 0.\n"
        "• Profile 2 – Edge Gateway (Raspberry Pi 4 / Industrial PC): 1.0 vCPU, 512 MB RAM, Swap = 0.\n"
        "• Profile 3 – IoT Embedded (Smart Meter / Sensor Node): 0.5 vCPU, 128 MB RAM, Swap = 0."
    )

    doc.add_heading("2.3. Hệ thống Giám sát Telemetry cgroups v2 & Triệt tiêu Nhiễu Cold-Start", level=2)
    doc.add_paragraph(
        "Toàn bộ công cụ telemetry được xây dựng trực tiếp trên giao diện Linux cgroups v2 đọc với tần số 80ms/mẫu:\n"
        "1. RAM thời gian thực & Đỉnh phần cứng: Đọc /sys/fs/cgroup/memory.current và /sys/fs/cgroup/memory.peak (thanh ghi phần cứng của kernel).\n"
        "2. Thời gian tiêu thụ CPU & Hiện tượng bóp xung: Đọc usage_usec và throttled_usec trong /sys/fs/cgroup/cpu.stat.\n"
        "3. Sự kiện hủy diệt bộ nhớ: Đọc oom_kill trong /sys/fs/cgroup/memory.events.\n"
        "Kỹ thuật xử lý triệt để nhiễu Cold-Start Page Cache: Kịch bản tự động kích hoạt một Warm-up Container chạy trong 2.5 giây nhằm nạp nóng Page Cache (glibc, Python binary, liboqs.so) trên Host, giúp các lần đo chính thức phản ánh chuẩn xác 100% bộ nhớ ẩn danh thực (43.0 MB Baseline RAM)."
    )

    doc.add_heading("3. THIẾT KẾ KỊCH BẢN THỰC NGHIỆM", level=1)
    doc.add_paragraph(
        "Quy trình đánh giá hiệu năng PERF-01 được cấu trúc thành 3 kịch bản liên hoàn:\n"
        "• Kịch bản Chuẩn bị Tải: Sinh trước các bộ dữ liệu giao dịch chuẩn hóa 500 txs và 2,000 txs để loại bỏ chi phí tạo chữ ký (Sign latency) của máy kiểm thử.\n"
        "• Kịch bản 1 (Vi mô - Micro-Benchmark 3x4): 12 phép thử (3 Cấu hình x 4 Thuật toán), nạp đồng thời 500 txs qua 8 luồng HTTP REST API, đo Ingestion TPS, Peak RAM, CPU Throttling.\n"
        "• Kịch bản 2 (Cực hạn - Extreme OOM Hunt): Ép trần 60MB RAM trên chip 0.5 vCPU, nạp liên tục 1,500 txs (từng lô 50 txs) để săn lùng sự kiện Linux Kernel OOM-Killer (Exit Code 137).\n"
        "• Kịch bản 3 (Vĩ mô - Macro-Benchmark Single DUT Mesh): 1 DUT trong cụm mạng 6 node kết nối Mesh qua WebSocket TLS 1.3 / ECDHE, đo thông lượng bão gossip 100 txs và độ trễ cam kết khối đào 100 txs."
    )

    doc.add_heading("4. TIẾN HÀNH THỰC NGHIỆM, KẾT QUẢ TỪNG BƯỚC & BÌNH LUẬN CHUYÊN SÂU", level=1)

    # Buoc 1
    doc.add_heading("Bước 1: Xây dựng Docker Image & Kiểm tra Tính hợp lệ của liboqs", level=2)
    doc.add_paragraph("Thao tác dòng lệnh:\n`docker build -t blockchain-node:perf -f perf/Dockerfile .`")
    doc.add_paragraph(
        "Kết quả kiểm tra xác nhận thư viện liboqs bên trong container hỗ trợ đầy đủ các thuật toán chữ ký số Hậu lượng tử FIPS 204: ML-DSA-44, ML-DSA-65, ML-DSA-87 bên cạnh các chuẩn Dilithium cũ."
    )

    # Buoc 2
    doc.add_heading("Bước 2: Sinh Bộ Dữ liệu Tải và Phân tích Tải trọng Mạng (Wire Overhead)", level=2)
    doc.add_paragraph("Thao tác dòng lệnh:\n`docker run --rm -v \"${PWD}:/app\" blockchain-node:perf python perf/generate_perf01_txs.py`")

    # Bang 1
    doc.add_paragraph("Bảng 1: Phân tích Kích thước Tải trọng Mạng Giữa Mật mã Cổ điển & Hậu Lượng tử").bold = True
    table1_data = [
        ["Thuật Toán Chữ Ký", "Cấp Độ An Toàn (NIST)", "Public Key (Hex)", "Chữ Ký (Hex)", "Kích Thước 1 Txn", "Hệ Số Phình To", "Khối 100 Txns"],
        ["ECDSA (secp256k1)", "Cổ điển (Không an toàn)", "130 B", "142 B", "499 Bytes", "1.0x (Chuẩn)", "54.7 KB"],
        ["ML-DSA-44", "Cấp độ 2 (SHA3-256)", "2,624 B", "4,840 B", "7,711 Bytes", "15.5x", "758.6 KB"],
        ["ML-DSA-65", "Cấp độ 3 (AES-192)", "3,904 B", "6,618 B", "10,769 Bytes", "21.6x", "1,057.2 KB"],
        ["ML-DSA-87", "Cấp độ 5 (AES-256)", "5,184 B", "9,254 B", "14,685 Bytes", "29.4x", "1,439.6 KB"]
    ]
    t1 = doc.add_table(rows=len(table1_data), cols=7)
    t1.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, row in enumerate(table1_data):
        for j, val in enumerate(row):
            cell = t1.cell(i, j)
            cell.text = val
            set_cell_margins(cell)
            if i == 0:
                set_cell_background(cell, "003366")
                p = cell.paragraphs[0]
                p.runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                p.runs[0].font.bold = True
            elif i % 2 == 1:
                set_cell_background(cell, "F2F2F2")

    doc.add_paragraph(
        "Bình luận chuyên sâu Bước 2:\n"
        "• Nguyên nhân toán học: Chữ ký ML-DSA dựa trên bài toán Module-LWE trên vành đa thức R_q. Khóa công khai chứa ma trận đa thức, còn chữ ký gồm vector đa thức z và vector gợi ý hint h, khiến dữ liệu nhị phân gốc đã chiếm 2.4 - 4.6 KB.\n"
        "• Phụ phí JSON + Hex: Việc biểu diễn các mảng byte sang chuỗi Hexadecimal làm phình gấp đôi kích thước. Do đó, một khối 100 giao dịch ML-DSA-87 phình to lên tới 1.44 MB (gấp 26.3 lần ECDSA), gây nghẽn nghiêm trọng cho tầng giao vận mạng."
    )

    # Buoc 3
    doc.add_heading("Bước 3: Thực thi Kịch bản Vi mô 3x4 & Bình luận Biểu đồ Rủi ro OOM (Hình 1)", level=2)
    doc.add_paragraph("Thao tác dòng lệnh:\n`python perf/perf01_stress_test.py`")

    # Bang 2
    doc.add_paragraph("Bảng 2: Ma Trận Đầy Đủ Kết Quả Thực Nghiệm Vi Mô 3x4 (Trích từ perf01_matrix.csv)").bold = True
    table2_data = [
        ["Cấu Hình", "Thuật Toán", "Thời Gian (s)", "TPS (tx/s)", "Peak RAM", "RAM %", "Avg CPU", "Norm CPU", "CPU Throttled", "Rủi Ro OOM"],
        ["Server (4 vCPU, 4GB)", "ECDSA", "1.160 s", "431.03", "47.13 MB", "1.15%", "133.47%", "33.37%", "0.0 ms", "AN TOÀN (<60%)"],
        ["Server", "ML-DSA-44", "0.725 s", "689.66", "51.94 MB", "1.27%", "150.93%", "37.73%", "0.0 ms", "AN TOÀN (<60%)"],
        ["Server", "ML-DSA-65", "0.763 s", "655.31", "53.98 MB", "1.32%", "153.70%", "38.42%", "0.0 ms", "AN TOÀN (<60%)"],
        ["Server", "ML-DSA-87", "0.810 s", "617.28", "54.89 MB", "1.34%", "152.35%", "38.09%", "0.0 ms", "AN TOÀN (<60%)"],
        ["Edge (1 vCPU, 512M)", "ECDSA", "1.676 s", "298.33", "48.82 MB", "9.54%", "99.19%", "99.19%", "680.86 ms", "AN TOÀN (<60%)"],
        ["Edge", "ML-DSA-44", "1.010 s", "495.05", "51.76 MB", "10.11%", "118.22%", "100.0%", "780.79 ms", "AN TOÀN (<60%)"],
        ["Edge", "ML-DSA-65", "1.022 s", "489.24", "53.30 MB", "10.41%", "114.54%", "100.0%", "855.14 ms", "AN TOÀN (<60%)"],
        ["Edge", "ML-DSA-87", "1.141 s", "438.21", "54.98 MB", "10.74%", "114.77%", "100.0%", "818.97 ms", "AN TOÀN (<60%)"],
        ["IoT (0.5 vCPU, 128M)", "ECDSA", "3.365 s", "148.59", "49.07 MB", "38.34%", "55.28%", "100.0%", "5412.53 ms", "AN TOÀN (<60%)"],
        ["IoT", "ML-DSA-44", "2.216 s", "225.63", "54.60 MB", "42.66%", "57.77%", "100.0%", "4931.10 ms", "AN TOÀN (<60%)"],
        ["IoT", "ML-DSA-65", "2.320 s", "215.52", "53.03 MB", "41.43%", "57.54%", "100.0%", "5410.28 ms", "AN TOÀN (<60%)"],
        ["IoT", "ML-DSA-87", "2.405 s", "207.90", "55.59 MB", "43.43%", "57.12%", "100.0%", "5798.36 ms", "AN TOÀN (<60%)"]
    ]
    t2 = doc.add_table(rows=len(table2_data), cols=10)
    t2.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, row in enumerate(table2_data):
        for j, val in enumerate(row):
            cell = t2.cell(i, j)
            cell.text = val
            set_cell_margins(cell, top=60, bottom=60, left=80, right=80)
            if i == 0:
                set_cell_background(cell, "003366")
                p = cell.paragraphs[0]
                p.runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                p.runs[0].font.bold = True
                p.runs[0].font.size = Pt(9.5)
            else:
                cell.paragraphs[0].runs[0].font.size = Pt(9)
                if i % 2 == 1:
                    set_cell_background(cell, "F2F2F2")

    # Chen Anh 1
    img1_path = RESULTS_DIR / "perf01_oom_risk_chart.png"
    if img1_path.exists():
        doc.add_paragraph()
        p_img1 = doc.add_paragraph()
        p_img1.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_img1.add_run().add_picture(str(img1_path), width=Inches(6.2))
        p_cap1 = doc.add_paragraph("Hình 1: Đánh giá Ranh giới Tài nguyên Node (Peak RAM, Ingestion TPS và Thời gian bóp nghẽn CPU CFS) khi tiếp nhận 500 giao dịch trên 3 Profile phần cứng.")
        p_cap1.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_cap1.runs[0].font.italic = True
        p_cap1.runs[0].font.size = Pt(10)

    doc.add_paragraph(
        "Bình luận & Phân tích Học thuật Chi tiết Cho Hình 1:\n"
        "1. Đồ thị 1 (Peak RAM): Với 500 txs, cả 3 profile đều an toàn dưới 60% trần cứng 128MB của thiết bị nhúng. RAM đỉnh của ECDSA đạt 47.1 - 49.1 MB, ML-DSA-87 đạt 54.9 - 55.6 MB. Trên IoT, mức này đã chiếm 43.43% trần cứng 128MB, tiêu hao gần một nửa bộ nhớ khả dụng.\n"
        "2. Đồ thị 2 (Nghịch lý TPS - PQC nhanh hơn ECDSA dù nặng hơn 15-29 lần): ML-DSA-44 đạt 689.66 tx/s trên Server (nhanh hơn ECDSA 431.03 tx/s gấp 1.6 lần) và 225.63 tx/s trên IoT (nhanh hơn ECDSA 148.59 tx/s gấp 1.5 lần). Nguyên nhân: (a) Về toán học, phép biến đổi số học NTT trên vành đa thức đạt O(n log n) nhanh hơn phép nhân vô hướng điểm elliptic s^-1(Hm.G + rQ); (b) Thư viện C liboqs giải phóng khóa Python GIL, giúp 8 worker threads chạy song song thực sự, trong khi python-ecdsa thuần Python bị tắc nghẽn nghiêm trọng vì tranh chấp GIL.\n"
        "3. Đồ thị 3 (Thời gian bóp nghẽn CPU CFS Throttled): Server 4 vCPU không hề bị bóp (0.0 ms). Edge 1 vCPU bị bóp nhẹ từ 681 ms đến 855 ms. Trên IoT 0.5 vCPU, áp lực quá tải bộc lộ khốc liệt: nhân Linux đã bóp nghẹt xung nhịp tiến trình tới 4,931 ms - 5,798 ms (trong đó ML-DSA-87 bị bóp nặng nhất tới 5.8 giây, gấp đôi thời gian thực thi thực tế)."
    )

    # Buoc 4
    doc.add_heading("Bước 4: Thực thi Kịch bản Cực hạn 60MB RAM & Bắt sống Sự kiện OOM-Killer (Hình 2)", level=2)
    doc.add_paragraph("Thao tác dòng lệnh:\n`python perf/perf01_stress_test.py (Part 2: Extreme OOM Hunt)`")

    # Bang 3
    doc.add_paragraph("Bảng 3: Dữ Liệu Quỹ Đạo Bộ Nhớ RAM & Thời Điểm OOM-Killed (Trích từ perf01_extreme_oom_matrix.csv)").bold = True
    table3_data = [
        ["Mốc Giao Dịch", "ML-DSA-87", "ML-DSA-65", "ML-DSA-44", "ECDSA", "Trần Cứng", "OOM ML-DSA-87", "OOM ML-DSA-65"],
        ["Tx #100", "48.39 MB", "43.20 MB", "46.34 MB", "43.76 MB", "60.0 MB", "Bình thường", "Bình thường"],
        ["Tx #300", "48.58 MB", "50.77 MB", "49.23 MB", "43.94 MB", "60.0 MB", "Bình thường", "Bình thường"],
        ["Tx #500", "55.09 MB", "53.00 MB", "51.32 MB", "44.77 MB", "60.0 MB", "Bình thường", "Bình thường"],
        ["Tx #700", "58.84 MB", "55.90 MB", "50.30 MB", "45.19 MB", "60.0 MB", "Bình thường", "Bình thường"],
        ["Tx #850", "59.50 MB", "54.82 MB", "51.68 MB", "45.62 MB", "60.0 MB", "Cận ngưỡng", "Bình thường"],
        ["Tx #900", "60.00 MB", "59.12 MB", "56.06 MB", "45.17 MB", "60.0 MB", "OOM-KILLED (Exit 137)", "Bình thường"],
        ["Tx #1100", "Đã chết", "58.55 MB", "59.21 MB", "45.93 MB", "60.0 MB", "-", "Cận ngưỡng"],
        ["Tx #1250", "Đã chết", "60.00 MB", "59.84 MB", "46.82 MB", "60.0 MB", "-", "Chạm trần"],
        ["Tx #1300", "Đã chết", "60.00 MB", "59.11 MB", "46.39 MB", "60.0 MB", "-", "OOM-KILLED (Exit 137)"],
        ["Tx #1500", "Đã chết", "Đã chết", "59.48 MB", "46.77 MB", "60.0 MB", "Thất bại", "Thất bại (SỐNG SÓT)"]
    ]
    t3 = doc.add_table(rows=len(table3_data), cols=8)
    t3.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, row in enumerate(table3_data):
        for j, val in enumerate(row):
            cell = t3.cell(i, j)
            cell.text = val
            set_cell_margins(cell, top=60, bottom=60, left=80, right=80)
            if i == 0:
                set_cell_background(cell, "8B0000")
                p = cell.paragraphs[0]
                p.runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                p.runs[0].font.bold = True
                p.runs[0].font.size = Pt(9.5)
            else:
                cell.paragraphs[0].runs[0].font.size = Pt(9)
                if i % 2 == 1:
                    set_cell_background(cell, "F2F2F2")

    # Chen Anh 2
    img2_path = RESULTS_DIR / "perf01_extreme_oom_chart.png"
    if img2_path.exists():
        doc.add_paragraph()
        p_img2 = doc.add_paragraph()
        p_img2.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_img2.add_run().add_picture(str(img2_path), width=Inches(6.2))
        p_cap2 = doc.add_paragraph("Hình 2: Quỹ đạo chiếm dụng bộ nhớ RAM và Bắt sống Sự kiện Kích hoạt Kernel OOM-Killer (Exit Code 137) trên Node IoT 60MB RAM.")
        p_cap2.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_cap2.runs[0].font.italic = True
        p_cap2.runs[0].font.size = Pt(10)

    doc.add_paragraph(
        "Bình luận & Phân tích Học thuật Chi tiết Cho Hình 2:\n"
        "• Khoảng đệm an toàn khả dụng (Memory Headroom): Với RAM nền tĩnh 43 MB, khoảng trống cho Mempool dưới trần 60 MB chỉ còn 17 MB.\n"
        "• Sự kiện OOM-Killer kép: ML-DSA-87 (~16.5 KB/tx in-memory) đẩy RAM chạm đỉnh 60.0 MB tại Tx #900 -> nhân Linux gửi tín hiệu SIGKILL hủy diệt tiến trình. ML-DSA-65 (~12 KB/tx) cầm cự đến Tx #1300 thì chạm đỉnh 60.0 MB và kích hoạt OOM-Killer thứ hai.\n"
        "• Vì sao ML-DSA-44 sống sót: Dù chạm mức nguy hiểm 59.84 MB tại Tx #1250 (99.7% trần), nhờ Python Garbage Collector thu hồi kịp thời biến đệm tạm thời sau mỗi chu kỳ HTTP POST, RAM giảm nhẹ về 59.48 MB và vượt qua an toàn toàn bộ 1,500 giao dịch.\n"
        "• Vì sao ECDSA phẳng hoàn toàn: Chỉ tốn 0.5 KB/tx, 1,500 giao dịch chỉ tốn 0.75 MB RAM, đường biểu diễn phẳng tuyệt đối ở mức 44.0 - 46.8 MB, chứng minh mật mã truyền thống có khả năng phòng thủ cạn kiệt bộ nhớ vượt trội so với PQC.\n"
        "• Ý nghĩa mã lỗi Exit Code 137: Bằng 128 + Signal 9 (SIGKILL). Đây là tín hiệu bất khả kháng từ tầng nhân hệ điều hành, không thể bị bắt (uncatchable) bởi bất kỳ khối lệnh try...except nào."
    )

    # Buoc 5
    doc.add_heading("Bước 5: Thực thi Kịch bản Vĩ mô Mạng 6-Node Mesh & Bình luận Dashboard (Hình 3)", level=2)
    doc.add_paragraph("Thao tác dòng lệnh:\n`python perf/perf01_macro_stress.py`")

    # Bang 4
    doc.add_paragraph("Bảng 4: Bảng 8 Chỉ Số Vàng Toàn Diện Macro-Benchmark (Trích từ perf01_macro_matrix.csv)").bold = True
    table4_data = [
        ["Nhóm Đánh Giá", "Chỉ Số Cốt Lõi", "ECDSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "Đánh Giá Thực Nghiệm"],
        ["1. Tải Trọng Mạng", "Txn / Khối 100 Txns", "0.49 KB / 54.7 KB", "7.71 KB / 758.6 KB", "10.77 KB / 1,057.2 KB", "14.69 KB / 1,439.6 KB", "Khối ML-DSA-87 phình gấp 26.3 lần do cấu trúc chữ ký lattice và phụ phí Hex."],
        ["2. Độ Trễ Đồng Thuận", "Verify Khối (S/E/IoT)", "115.0 / 124.7 / 193.1 ms", "6.8 / 9.6 / 12.1 ms", "14.2 / 19.0 / 14.2 ms", "21.1 / 21.4 / 18.7 ms", "ML-DSA nhờ C liboqs NTT nhanh gấp 10-16 lần so với python-ecdsa."],
        ["", "Độ trễ Truyền TLS 1.3", "3.7 / 4.4 / 4.6 ms", "34.2 / 35.0 / 31.9 ms", "49.1 / 50.6 / 54.3 ms", "65.8 / 66.5 / 74.0 ms", "Ở PQC, độ trễ truyền mạng chiếm 70%-80% tổng thời gian cam kết."],
        ["", "Tổng Cam Kết Khối", "118.9 / 129.5 / 197.9 ms", "42.5 / 46.3 / 45.7 ms", "65.5 / 72.0 / 71.7 ms", "90.0 / 90.9 / 95.5 ms", "Tổng thời gian từ lúc Miner phát sóng đến khi DUT xác thực và ghi sổ cái."],
        ["3. Bão Gossip", "Thông Lượng Ingest", "146.7 / 154.1 / 103.1 TPS", "176.1 / 121.9 / 63.4 TPS", "165.4 / 108.0 / 55.8 TPS", "140.3 / 97.4 / 39.8 TPS", "Trên IoT, thông lượng ML-DSA-87 giảm 2.6 lần so với ECDSA do nghẽn I/O."],
        ["", "Lọc Trùng / BW Đỉnh", "351 KB/s (Chặn 600 gói)", "4,295 KB/s (Chặn 800 gói)", "5,870 KB/s (Chặn 900 gói)", "5,600 KB/s (Chặn 881 gói)", "seen_tx_hashes chặn thành công 85%-90% gói tin trùng lặp dội từ 5 peers."],
        ["4. cgroups v2", "Thời Gian Bóp CPU", "0 / 322 / 1,627 ms (69%)", "0 / 1,051 / 3,932 ms (74%)", "0 / 1,447 / 5,259 ms (76%)", "0 / 1,624 / 8,732 ms (79%)", "ML-DSA-87 đè nặng CPU IoT gấp 5.3 lần ECDSA (bị ngắt 79.4% chu kỳ)."],
        ["", "Đỉnh RAM / % Trần IoT", "50.1 MB (39.1%)", "78.9 MB (61.6%)", "85.9 MB (67.1%)", "107.5 MB (84.0%)", "Chỉ với 100 txs, ML-DSA-87 chiếm 84% trần 128MB, cận kề vực thẳm OOM."]
    ]
    t4 = doc.add_table(rows=len(table4_data), cols=7)
    t4.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, row in enumerate(table4_data):
        for j, val in enumerate(row):
            cell = t4.cell(i, j)
            cell.text = val
            set_cell_margins(cell, top=60, bottom=60, left=80, right=80)
            if i == 0:
                set_cell_background(cell, "003366")
                p = cell.paragraphs[0]
                p.runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                p.runs[0].font.bold = True
                p.runs[0].font.size = Pt(9.5)
            else:
                cell.paragraphs[0].runs[0].font.size = Pt(8.5)
                if i % 2 == 1:
                    set_cell_background(cell, "F2F2F2")

    # Chen Anh 3
    img3_path = RESULTS_DIR / "perf01_macro_chart.png"
    if img3_path.exists():
        doc.add_paragraph()
        p_img3 = doc.add_paragraph()
        p_img3.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_img3.add_run().add_picture(str(img3_path), width=Inches(6.2))
        p_cap3 = doc.add_paragraph("Hình 3: Dashboard 4-Panel Đánh Giá Thực Nghiệm Toàn Diện Node DUT trong Mạng Lưới P2P Mesh 6 Nodes qua WebSocket TLS 1.3.")
        p_cap3.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_cap3.runs[0].font.italic = True
        p_cap3.runs[0].font.size = Pt(10)

    doc.add_paragraph(
        "Bình luận & Phân tích Học thuật Chi tiết Cho Hình 3:\n"
        "• Panel 1 (Thời gian Cam kết Khối: Verify CPU vs Wire Transit): Thể hiện sự chuyển dịch điểm nghẽn hệ thống từ CPU-bound sang Network I/O-bound. Với ECDSA, CPU verify chiếm tới 97.5% tổng độ trễ. Với PQC ML-DSA, CPU verify cực nhanh (12 - 18 ms) nhưng truyền tải khối 0.76 - 1.44 MB qua TLS 1.3 chiếm tới 70% - 80% thời gian (32 - 74 ms).\n"
        "• Panel 2 (Thông lượng Mempool & Lọc trùng): Kích thước khối tăng từ 54.7 KB lên 1,439.6 KB khiến Ingestion TPS của IoT giảm từ 103.1 TPS xuống 39.8 TPS (suy giảm 61.4%). Thuật toán seen_tx_hashes lọc thành công 85%-90% gói tin trùng lặp dội từ 5 peers.\n"
        "• Panel 3 (Áp lực bóp nghẽn CPU cgroups v2): Server không bị bóp (0 ms). Edge bị bóp từ 322 ms lên 1,624 ms. IoT bị bóp nghẹt từ 1,627 ms lên tới kỷ lục 8,732 ms (79.4% chu kỳ hoạt động) đối với ML-DSA-87.\n"
        "• Panel 4 (Cảnh báo ngưỡng RAM trên IoT): Với 100 txs trong mạng P2P, ML-DSA-87 đẩy mức RAM lên tới 107.45 MB (chiếm 84.0% trần cứng 128MB), chỉ còn cách vực thẳm OOM-Killer đúng 20.5 MB."
    )

    doc.add_heading("5. TỔNG KẾT & KHUYẾN NGHỊ KIẾN TRÚC CHO HỆ THỐNG BLOCKCHAIN HẬU LƯỢNG TỬ", level=1)
    doc.add_paragraph(
        "Dựa trên các kết quả định lượng, nhóm đề xuất các khuyến nghị kiến trúc sau:\n"
        "1. Khuyến nghị theo phân khúc phần cứng:\n"
        "   - Thiết bị IoT / Cảm biến nhúng (<= 128MB RAM, <= 0.5 vCPU): Khuyến nghị sử dụng ML-DSA-44 (NIST Level 2), giới hạn khối <= 50 txs; tuyệt đối tránh dùng ML-DSA-87.\n"
        "   - Edge Gateway (Raspberry Pi 4, 512MB RAM): Khuyến nghị sử dụng ML-DSA-65 (NIST Level 3 - Sweet Spot), cân bằng hoàn hảo giữa an toàn mã hóa AES-192 và tài nguyên máy.\n"
        "   - Cloud Server / Miner (>= 4 vCPU, >= 4GB RAM): Hoàn toàn đủ khả năng gánh cả ML-DSA-65 và ML-DSA-87.\n"
        "2. Đề xuất cải tiến kỹ thuật:\n"
        "   - Chuyển đổi sang Chuẩn Nhị Phân (Protobuf / CBOR / MessagePack): Thay thế JSON + Hex để giảm ngay lập tức 40% - 48% kích thước khối dữ liệu trên đường truyền.\n"
        "   - Triển khai Cơ chế Giới hạn Mempool Theo Dung Lượng Byte (Byte-Bounded Mempool Eviction): Giới hạn hàng đợi Mempool theo Megabyte (ví dụ tối đa 10MB trên IoT) thay vì đếm số lượng giao dịch, tự động loại bỏ giao dịch phí thấp khi đầy hàng đợi để bảo vệ an toàn tính mạng cho tiến trình."
    )

    doc.add_heading("6. ĐÓNG GÓP CỦA PERF-01 TRONG TỔNG THỂ ĐỒ ÁN", level=1)
    doc.add_paragraph(
        "Kịch bản PERF-01 đóng vai trò là chiếc cầu nối thực nghiệm vững chắc trong toàn bộ đồ án:\n"
        "• Kết nối với Phần 1 (SEC-01..04): Làm sáng tỏ cái giá phải trả về tài nguyên phần cứng để đạt được tính an toàn trước tấn công giải mã lượng tử, lật bit và phân tích kênh kề TVLA.\n"
        "• Kết nối với Phần 2 (NET-01..02): Cung cấp số liệu chính xác về kích thước khối (1.44 MB) và độ trễ truyền tải TLS 1.3 làm cơ sở giải thích hiện tượng phân mảnh gói tin TCP và tỷ lệ sinh nhánh rẽ phân kỳ (Fork rate).\n"
        "• Tính chuẩn mực DevOps: Đóng gói Docker, giám sát cgroups v2 thời gian thực, khử nhiễu Warm-up Page Cache và mô phỏng mạng lưới Mesh 6 nodes đem lại độ tin cậy và giá trị học thuật cao nhất cho đồ án."
    )

    try:
        doc.save(str(DOCX_PATH))
        print(f"[+] Da tao thanh cong file Word: {DOCX_PATH}")
    except PermissionError:
        fallback_path = RESULTS_DIR / "BAO_CAO_PERF01_updated.docx"
        doc.save(str(fallback_path))
        print(f"[!] BAO_CAO_PERF01.docx dang mo trong Microsoft Word. Da luu ban moi vao: {fallback_path}")

if __name__ == '__main__':
    create_report_docx()
