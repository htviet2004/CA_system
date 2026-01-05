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
from pypdf import PdfReader, PdfWriter
from datetime import datetime


class PDFStampService:
    """Service để thêm visual stamp vào PDF"""
    
    @staticmethod
    def create_stamp_overlay(box, username, timestamp=None, style='dut_professional'):
        """
        Tạo PDF overlay chứa visual stamp
        
        Args:
            box: (x1, y1, x2, y2) tọa độ trong PDF points
            username: Tên người ký
            timestamp: Thời gian (datetime object)
            style: Style của stamp
            
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
        if style == 'dut_professional':
            PDFStampService._draw_dut_stamp(c, x1, y1, width, height, username, timestamp)
        elif style == 'minimal':
            PDFStampService._draw_minimal_stamp(c, x1, y1, width, height, username, timestamp)
        else:
            PDFStampService._draw_simple_stamp(c, x1, y1, width, height, username, timestamp)
        
        c.save()
        buffer.seek(0)
        return buffer.getvalue()
    
    @staticmethod
    def _draw_dut_stamp(c, x, y, width, height, username, timestamp):
        """Vẽ stamp style Adobe Sign - chuyên nghiệp, tối giản"""
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
        
        # Main text: "Digitally signed by"
        c.setFont("Helvetica", 7)
        c.drawString(text_x, y + height - 15, "Digitally signed by")
        
        # Username (bold, lớn hơn)
        c.setFont("Helvetica-Bold", 9)
        c.drawString(text_x, y + height - 28, username)
        
        # Date
        c.setFont("Helvetica", 7)
        ts = timestamp.strftime("%Y-%m-%d %H:%M:%S %Z") if timestamp else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.drawString(text_x, y + height - 40, f"Date: {ts}")
        
        # Organization (optional)
        c.setFont("Helvetica", 6)
        c.setFillColor(HexColor('#666666'))
        c.drawString(text_x, y + height - 52, "Da Nang University of Science and Technology")
        
        # Footer - validation indicator
        c.setFont("Helvetica", 6)
        c.setFillColor(HexColor('#0078d4'))
        c.drawString(x + 5, y + 5, "Valid digital signature")
    
    @staticmethod
    def _draw_minimal_stamp(c, x, y, width, height, username, timestamp):
        """Vẽ stamp tối giản"""
        # Background xám nhạt
        c.setFillColor(HexColor('#f3f4f6'))
        c.rect(x, y, width, height, fill=1, stroke=0)
        
        # Border xám
        c.setStrokeColor(HexColor('#9ca3af'))
        c.setLineWidth(1)
        c.rect(x, y, width, height, fill=0, stroke=1)
        
        # Text đen
        c.setFillColor(HexColor('#000000'))
        c.setFont("Helvetica", 8)
        
        ts = timestamp.strftime("%Y-%m-%d %H:%M") if timestamp else datetime.now().strftime("%Y-%m-%d %H:%M")
        
        c.drawString(x + 5, y + height - 15, f"Signed by: {username}")
        c.drawString(x + 5, y + height - 28, f"Date: {ts}")
    
    @staticmethod
    def _draw_simple_stamp(c, x, y, width, height, username, timestamp):
        """Vẽ stamp đơn giản"""
        # Border đen
        c.setStrokeColor(HexColor('#000000'))
        c.setLineWidth(1)
        c.rect(x, y, width, height, fill=0, stroke=1)
        
        # Text
        c.setFillColor(HexColor('#000000'))
        c.setFont("Helvetica", 8)
        
        ts = timestamp.strftime("%Y-%m-%d %H:%M:%S") if timestamp else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        c.drawString(x + 5, y + height - 15, f"{username}")
        c.drawString(x + 5, y + height - 28, f"{ts}")
    
    @staticmethod
    def add_stamp_to_pdf(input_pdf_path, output_pdf_path, page_num, box, username, timestamp=None, style='dut_professional'):
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
            
        Returns:
            str: Đường dẫn file output
        """
        # Tạo stamp overlay
        stamp_pdf_data = PDFStampService.create_stamp_overlay(box, username, timestamp, style)
        
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
