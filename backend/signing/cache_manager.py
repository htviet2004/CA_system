import os
import tempfile
import threading
import time
import shutil
from datetime import datetime, timedelta
from django.conf import settings
from django.contrib.auth.models import User
from django.utils import timezone


class SignedPDFCache:
    """
    Cache quản lý PDF đã ký cho user.
    - Lưu tối đa 5 PDFs per user
    - Mỗi PDF tồn tại 1 giờ (TTL)
    - File PDF lưu trong hệ thống tập tin: media/signed_pdfs/{username}/
    - Database chỉ lưu metadata: ID, tên, thời gian ký
    - Log các PDFs đã ký (không xóa sau timeout)
    """
    
    def __init__(self, ttl_seconds=3600, max_pdfs_per_user=5):
        """
        Args:
            ttl_seconds: Thời gian sống của cache (mặc định 1 giờ)
            max_pdfs_per_user: Số PDF tối đa per user (mặc định 5)
        """
        self.ttl_seconds = ttl_seconds
        self.max_pdfs_per_user = max_pdfs_per_user
        self.lock = threading.Lock()
        self.cleanup_thread = None
        self.running = False
        self._start_cleanup_thread()
    
    def _start_cleanup_thread(self):
        """Khởi động thread dọn dẹp cache tự động"""
        if not self.running:
            self.running = True
            self.cleanup_thread = threading.Thread(
                target=self._cleanup_expired,
                daemon=True
            )
            self.cleanup_thread.start()
    
    def _cleanup_expired(self):
        """Xóa các file PDF hết hạn và đánh dấu trong database"""
        while self.running:
            try:
                with self.lock:
                    from signing.models import SignedPDF
                    
                    # Tìm các record hết hạn cache nhưng vẫn là cached
                    expired_records = SignedPDF.objects.filter(
                        is_cached=True,
                        created_at__lt=timezone.now() - timedelta(seconds=self.ttl_seconds)
                    )
                    
                    for record in expired_records:
                        print(f"[CACHE] Marking expired: {record.filename} (ID: {record.pdf_id})")
                        # Xóa file khỏi hệ thống tập tin
                        self._delete_pdf_file(record.user.username, record.pdf_id)
                        # Đánh dấu là hết hạn trong database nhưng vẫn giữ trong log
                        record.mark_expired()
                
                # Kiểm tra mỗi 5 phút
                time.sleep(300)
            except Exception as e:
                print(f"[CACHE] Cleanup error: {e}")
                time.sleep(60)
    
    def _get_pdf_dir(self, username):
        """Lấy đường dẫn thư mục cho PDF của user"""
        # Lưu trong pdf_achiever/{username}/ thay vì media/signed_pdfs/
        pdf_base = os.path.join(settings.BASE_DIR, 'pdf_achiever')
        user_pdf_dir = os.path.join(pdf_base, username)
        return user_pdf_dir
    
    def _ensure_pdf_dir(self, username):
        """Tạo thư mục cho PDF nếu chưa tồn tại"""
        pdf_dir = self._get_pdf_dir(username)
        os.makedirs(pdf_dir, exist_ok=True)
        return pdf_dir
    
    def _delete_pdf_file(self, username, pdf_id):
        """Xóa file PDF"""
        try:
            pdf_dir = self._get_pdf_dir(username)
            pdf_path = os.path.join(pdf_dir, f"{pdf_id}.pdf")
            if os.path.exists(pdf_path):
                os.remove(pdf_path)
                print(f"[CACHE] Deleted PDF file: {pdf_path}")
        except Exception as e:
            print(f"[CACHE] Error deleting PDF file: {e}")
    
    def save(self, user, pdf_path, original_filename, signer_name='', title='', custom_text='', reason='', location=''):
        """
        Lưu PDF đã ký vào hệ thống tập tin và database metadata.
        
        Args:
            user: Django User object
            pdf_path: Đường dẫn file PDF tạm thời
            original_filename: Tên file gốc
            signer_name: Tên người ký (không lưu, chỉ dùng cho stamp)
            title: Chức danh (không lưu, chỉ dùng cho stamp)
            custom_text: Dòng chữ tùy chọn (không lưu, chỉ dùng cho stamp)
            reason: Lý do ký (không lưu, chỉ dùng cho stamp)
            location: Vị trí ký (không lưu, chỉ dùng cho stamp)
        
        Returns:
            SignedPDF: Đối tượng SignedPDF vừa tạo (metadata)
        """
        try:
            from signing.models import SignedPDF
            import uuid
            
            # Tạo ID unique cho PDF
            pdf_id = str(uuid.uuid4())
            
            # Đảm bảo thư mục tồn tại
            user_pdf_dir = self._ensure_pdf_dir(user.username)
            
            # Lưu file PDF
            target_path = os.path.join(user_pdf_dir, f"{pdf_id}.pdf")
            shutil.copy2(pdf_path, target_path)
            print(f"[CACHE] Saved PDF file: {target_path}")
            
            # Tạo record metadata trong database
            # Explicitly set time để đảm bảo signed_at và created_at là thời gian hiện tại
            now = timezone.now()
            signed_pdf = SignedPDF.objects.create(
                pdf_id=pdf_id,
                user=user,
                filename=original_filename,
                signed_at=now,
                created_at=now
            )
            
            print(f"[CACHE DEBUG] Created PDF record - pdf_id: {pdf_id}, signed_at: {signed_pdf.signed_at}, created_at: {signed_pdf.created_at}")
            
            # Kiểm tra và xử lý quá hạn mức tối đa
            self._enforce_max_pdfs(user)
            
            print(f"[CACHE] Saved PDF metadata for user: {user.username}, PDF ID: {pdf_id}")
            return signed_pdf
            
        except Exception as e:
            print(f"[CACHE] Error saving PDF: {e}")
            raise
    
    def _enforce_max_pdfs(self, user):
        """
        Kiểm tra số PDF của user, nếu vượt quá max_pdfs_per_user thì xóa PDF cũ nhất.
        """
        try:
            from signing.models import SignedPDF
            
            # Đếm số PDF đang cached của user
            cached_count = SignedPDF.objects.filter(
                user=user,
                is_cached=True
            ).count()
            
            if cached_count > self.max_pdfs_per_user:
                # Lấy PDF cũ nhất (đánh dấu là hết hạn, xóa file)
                oldest = SignedPDF.objects.filter(
                    user=user,
                    is_cached=True
                ).order_by('signed_at').first()
                
                if oldest:
                    print(f"[CACHE] Max PDFs reached ({cached_count}), removing oldest: {oldest.filename}")
                    self._delete_pdf_file(user.username, oldest.pdf_id)
                    oldest.mark_expired()
        except Exception as e:
            print(f"[CACHE] Error enforcing max PDFs: {e}")
    
    def get_active_pdfs(self, user):
        """
        Lấy danh sách PDF đang cached (chưa hết hạn) của user.
        
        Args:
            user: Django User object
        
        Returns:
            list: Danh sách SignedPDF objects
        """
        try:
            from signing.models import SignedPDF
            
            with self.lock:
                # Lấy các PDF còn cached
                pdfs = SignedPDF.objects.filter(
                    user=user,
                    is_cached=True
                ).order_by('-signed_at')
                
                # Lọc các PDF chưa hết hạn
                active_pdfs = []
                for pdf in pdfs:
                    # So sánh aware datetime với aware datetime
                    now_aware = timezone.now()
                    elapsed = (now_aware - pdf.created_at).total_seconds()
                    remaining = self.ttl_seconds - elapsed
                    print(f"[CACHE DEBUG] PDF: {pdf.pdf_id}, created_at: {pdf.created_at}, now: {now_aware}, elapsed: {elapsed}s, remaining: {remaining}s, is_cached: {pdf.is_cached}")
                    
                    if not pdf.is_expired(self.ttl_seconds):
                        active_pdfs.append(pdf)
                    else:
                        # Nếu hết hạn, xóa file và đánh dấu
                        print(f"[CACHE] Marking PDF {pdf.pdf_id} as expired")
                        self._delete_pdf_file(user.username, pdf.pdf_id)
                        pdf.mark_expired()
                
                return active_pdfs
        except Exception as e:
            print(f"[CACHE] Error getting active PDFs: {e}")
            return []
    
    def verify_cache_status(self, user):
        """
        Kiểm tra và cập nhật trạng thái cache của user.
        Check TTL + file tồn tại + cleanup expired files.
        
        Returns:
            dict: {'active': count, 'expired_ttl': count, 'file_missing': count}
        """
        try:
            from signing.models import SignedPDF
            
            with self.lock:
                all_pdfs = SignedPDF.objects.filter(user=user).order_by('-signed_at')
                
                stats = {
                    'active': 0,
                    'expired_ttl': 0,
                    'file_missing': 0
                }
                
                for pdf in all_pdfs:
                    reason = pdf.get_expiry_reason(self.ttl_seconds)
                    
                    if reason == 'active':
                        stats['active'] += 1
                    elif reason == 'ttl':
                        stats['expired_ttl'] += 1
                        # Auto-cleanup: mark as expired nếu chưa
                        if pdf.is_cached:
                            pdf.mark_expired()
                            print(f"[CACHE] Auto-marked as TTL expired: {pdf.pdf_id}")
                    elif reason == 'file_missing':
                        stats['file_missing'] += 1
                        # Auto-cleanup: mark as expired nếu file missing
                        if pdf.is_cached:
                            pdf.mark_expired()
                            print(f"[CACHE] Auto-marked as file missing: {pdf.pdf_id}")
                
                print(f"[CACHE] Verify status for {user.username}: {stats}")
                return stats
        except Exception as e:
            print(f"[CACHE] Error verifying cache status: {e}")
            return {'active': 0, 'expired_ttl': 0, 'file_missing': 0}
    
    def get_all_pdfs_log(self, user):
        """
        Lấy toàn bộ log PDF của user (bao gồm cả đã hết hạn).
        
        Args:
            user: Django User object
        
        Returns:
            list: Danh sách tất cả SignedPDF objects
        """
        try:
            from signing.models import SignedPDF
            
            with self.lock:
                pdfs = SignedPDF.objects.filter(user=user).order_by('-signed_at')
                return list(pdfs)
        except Exception as e:
            print(f"[CACHE] Error getting PDF log: {e}")
            return []
    
    def get_pdf_file(self, user, pdf_id):
        """
        Lấy file PDF theo ID.
        
        Args:
            user: Django User object
            pdf_id: ID của PDF
        
        Returns:
            tuple: (file_path, filename) hoặc (None, None)
        """
        try:
            from signing.models import SignedPDF
            
            pdf_record = SignedPDF.objects.get(pdf_id=pdf_id, user=user)
            pdf_path = os.path.join(self._get_pdf_dir(user.username), f"{pdf_id}.pdf")
            
            if os.path.exists(pdf_path):
                return (pdf_path, pdf_record.filename)
            else:
                print(f"[CACHE] PDF file not found: {pdf_path}")
                return (None, None)
        except Exception as e:
            print(f"[CACHE] Error getting PDF file: {e}")
            return (None, None)
    
    def delete(self, user, pdf_id):
        """
        Xóa PDF từ cache (vẫn giữ trong log nếu đã hết hạn).
        
        Args:
            user: Django User object
            pdf_id: ID của PDF
        """
        try:
            from signing.models import SignedPDF
            
            with self.lock:
                pdf_record = SignedPDF.objects.get(pdf_id=pdf_id, user=user)
                
                if pdf_record.is_cached:
                    # Xóa file
                    self._delete_pdf_file(user.username, pdf_id)
                    # Đánh dấu là hết hạn
                    pdf_record.mark_expired()
                    print(f"[CACHE] Deleted cached PDF: {pdf_id}")
        except SignedPDF.DoesNotExist:
            print(f"[CACHE] PDF record not found: {pdf_id}")
        except Exception as e:
            print(f"[CACHE] Error deleting PDF: {e}")
    
    def delete_all(self, user):
        """
        Xóa toàn bộ PDF cached của user.
        
        Args:
            user: Django User object
        """
        try:
            from signing.models import SignedPDF
            
            with self.lock:
                pdfs = SignedPDF.objects.filter(user=user, is_cached=True)
                for pdf in pdfs:
                    self._delete_pdf_file(user.username, pdf.pdf_id)
                    pdf.mark_expired()
                print(f"[CACHE] Deleted all cached PDFs for user: {user.username}")
        except Exception as e:
            print(f"[CACHE] Error deleting all PDFs: {e}")
    
    def clear_all(self):
        """Xóa toàn bộ cache từ hệ thống tập tin và database"""
        try:
            from signing.models import SignedPDF
            
            with self.lock:
                pdfs = SignedPDF.objects.filter(is_cached=True)
                for pdf in pdfs:
                    self._delete_pdf_file(pdf.user.username, pdf.pdf_id)
                    pdf.mark_expired()
                print("[CACHE] Cleared all cached PDFs")
        except Exception as e:
            print(f"[CACHE] Error clearing all cache: {e}")
    
    def shutdown(self):
        """Tắt cleanup thread"""
        self.running = False
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5)
        self.clear_all()


# Khởi tạo global cache instance
# TTL và max PDFs có thể cấu hình trong settings
TTL = getattr(settings, 'SIGNED_PDF_CACHE_TTL', 3600)  # Mặc định 1 giờ
MAX_PDFS = getattr(settings, 'SIGNED_PDF_MAX_PER_USER', 5)  # Mặc định 5 PDFs
signed_pdf_cache = SignedPDFCache(ttl_seconds=TTL, max_pdfs_per_user=MAX_PDFS)

