"""
PDF Stamp Service - Thêm visual stamp (UI) vào PDF trước khi ký

Luồng: 
1. Add visual stamp (text, màu sắc, logo) vào PDF
2. Sign invisible signature hoặc signature field nhỏ 1x1
"""
import io
import os
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from pypdf import PdfReader, PdfWriter
from datetime import datetime

# Đăng ký font Unicode để hỗ trợ tiếng Việt
try:
    # Thử sử dụng font Arial Unicode (có sẵn trên Windows)
    pdfmetrics.registerFont(TTFont('ArialUnicode', 'arial.ttf'))
    pdfmetrics.registerFont(TTFont('ArialUnicode-Bold', 'arialbd.ttf'))
    FONT = 'ArialUnicode'
    FONT_BOLD = 'ArialUnicode-Bold'
    print("[FONT] Using Arial Unicode for Vietnamese support")
except:
    # Fallback: dùng Helvetica (không có tiếng Việt)
    FONT = 'Helvetica'
    FONT_BOLD = 'Helvetica-Bold'
    print("[FONT] Warning: Arial not found, using Helvetica (no Vietnamese support)")


class PDFStampService:
    """Service để thêm visual stamp vào PDF"""
    
    @staticmethod
    def create_stamp_overlay(box, username, timestamp=None, style='dut_professional', text_config=None):
        """
        Tạo PDF overlay chứa visual stamp
        
        Args:
            box: (x1, y1, x2, y2) tọa độ trong PDF points
            username: Tên người ký
            timestamp: Thời gian (datetime object)
            style: Style của stamp
            text_config: Dict chứa text tùy chỉnh
                {
                    'signer_name': 'Nguyễn Văn A',  # Tên người ký (thay thế username)
                    'title': 'Giám đốc',  # Chức danh
                    'custom_text': 'Đã phê duyệt'  # Dòng chữ tùy chọn
                }
            
        Returns:
            bytes: PDF data chứa stamp overlay
        """
        x1, y1, x2, y2 = box
        width = x2 - x1
        height = y2 - y1
        
        # Tạo in-memory PDF với stamp
        # Sử dụng A4 page size để merge dễ dàng
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=(595, 842))  # A4 standard
        
        # Vẽ stamp tại vị trí (x1, y1) trên page
        PDFStampService._draw_dut_stamp(c, x1, y1, width, height, username, timestamp, text_config)
        
        c.save()
        buffer.seek(0)
        return buffer.getvalue()
    
    @staticmethod
    def _draw_dut_stamp(c, x, y, width, height, username, timestamp, text_config=None):
        if text_config is None:
            text_config = {}
        
        signer_name = text_config.get('signer_name', username)
        department = text_config.get('department', '')
        title = text_config.get('title', '')
        custom_text = text_config.get('custom_text', '')
        
        # Background trắng với viền xanh nhạt
        c.setFillColor(HexColor('#ffffff'))
        c.rect(x, y, width, height, fill=1, stroke=0)
        
        # Border xanh nhạt
        c.setStrokeColor(HexColor('#0078d4'))
        c.setLineWidth(1.5)
        c.rect(x, y, width, height, fill=0, stroke=1)
        
        # Icon checkmark circle (vẽ hình tròn với dấu tick)
        icon_x = x + 12
        icon_y = y + height/2
        icon_radius = 8
        
        # Circle xanh
        c.setFillColor(HexColor('#0078d4'))
        c.circle(icon_x, icon_y, icon_radius, fill=1, stroke=0)
        
        # Checkmark (vẽ dấu tick màu trắng)
        c.setStrokeColor(HexColor('#ffffff'))
        c.setLineWidth(1.5)
        c.line(icon_x - 3, icon_y, icon_x - 1, icon_y - 3)
        c.line(icon_x - 1, icon_y - 3, icon_x + 3, icon_y + 3)
        
        # Text bên phải icon
        text_x = x + 28
        c.setFillColor(HexColor('#000000'))
        
        current_y = y + height - 15
        
        # Main text: "Digitally signed by"
        c.setFont(FONT, 7)
        c.drawString(text_x, current_y, "Digitally signed by")
        current_y -= 13
        
        # Signer name (bold, lớn hơn)
        c.setFont(FONT_BOLD, 9)
        c.drawString(text_x, current_y, signer_name)
        current_y -= 10
        
        # Department (nếu có)
        if department:
            c.setFont(FONT, 7)
            c.drawString(text_x, current_y, department)
            current_y -= 10
        
        # Title (nếu có)
        if title:
            c.setFont(FONT, 7)
            c.drawString(text_x, current_y, title)
            current_y -= 10
        
        # Custom text (nếu có)
        if custom_text:
            c.setFont(FONT, 7)  # Không dùng Oblique vì font custom không có
            c.setFillColor(HexColor('#0078d4'))
            c.drawString(text_x, current_y, custom_text)
            current_y -= 10
            c.setFillColor(HexColor('#000000'))
        
        # Date
        c.setFont(FONT, 7)
        ts = timestamp.strftime("%Y-%m-%d %H:%M:%S") if timestamp else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.drawString(text_x, current_y, f"Date: {ts}")
        
        # Footer - validation indicator
        c.setFont(FONT, 6)
        c.setFillColor(HexColor('#0078d4'))
        c.drawString(x + 5, y + 5, "Valid digital signature")
    
    @staticmethod
    def add_stamp_to_pdf(input_pdf_path, output_pdf_path, page_num, box, username, timestamp=None, style='dut_professional', text_config=None):
        """
        Thêm visual stamp vào PDF
        
        Args:
            input_pdf_path: Đường dẫn PDF gốc
            output_pdf_path: Đường dẫn PDF output (với stamp)
            page_num: Số trang (0-indexed)
            box: (x1, y1, x2, y2) tọa độ stamp
            username: Tên người ký
            timestamp: Thời gian
            style: Style stamp
            text_config: Dict chứa text tùy chỉnh
            
        Returns:
            str: Đường dẫn file output
        """
        # Tạo stamp overlay
        stamp_pdf_data = PDFStampService.create_stamp_overlay(box, username, timestamp, style, text_config)
        
        # Đọc PDF gốc
        reader = PdfReader(input_pdf_path)
        writer = PdfWriter()
        
        # Đọc stamp overlay
        stamp_reader = PdfReader(io.BytesIO(stamp_pdf_data))
        stamp_page = stamp_reader.pages[0]
        
        # Merge stamp vào page
        for i, page in enumerate(reader.pages):
            if i == page_num:
                # Merge stamp overlay lên page hiện tại
                page.merge_page(stamp_page)
                print(f"[STAMP DEBUG] Merged stamp onto page {i}")
            writer.add_page(page)
        
        # Ghi file output
        with open(output_pdf_path, 'wb') as f:
            writer.write(f)
        
        print(f"[STAMP DEBUG] Written stamped PDF to {output_pdf_path}, size: {os.path.getsize(output_pdf_path)} bytes")
        
        return output_pdf_path
