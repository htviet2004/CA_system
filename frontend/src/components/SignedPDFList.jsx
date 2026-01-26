import React, { useState, useEffect } from 'react';
import { Download, FileText, Clock, RefreshCw } from 'lucide-react';
import { getSignedPdfsLog, downloadSignedPdf, verifyCacheStatus } from '../api';
import '../static/styles/signed-pdfs.css';

export default function SignedPDFList({ username, showMessage }) {
  const [pdfs, setPdfs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState(null);
  const [error, setError] = useState(null);
  const [cacheStats, setCacheStats] = useState(null);

  useEffect(() => {
    loadPdfLog();
  }, [username]);

  const loadPdfLog = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Verify cache status trước (cleanup expired + check file existence)
      try {
        const stats = await verifyCacheStatus();
        setCacheStats(stats.stats);
        console.log('[CACHE VERIFY]', stats.message);
      } catch (err) {
        console.error('Error verifying cache status:', err);
      }
      
      // Sau đó lấy danh sách PDF
      const data = await getSignedPdfsLog();
      setPdfs(data.pdfs || []);
    } catch (err) {
      console.error('Error loading PDF log:', err);
      setError('Lỗi khi tải danh sách PDF');
      setPdfs([]);
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async (pdf) => {
    // Check từ remaining_seconds
    const remaining = pdf.remaining_seconds ?? 3600;
    if (remaining <= 0 || !pdf.is_cached) {
      showMessage('PDF này đã hết hạn cache và không thể tải xuống', 'error');
      return;
    }

    try {
      setDownloading(pdf.pdf_id);
      const blob = await downloadSignedPdf(pdf.pdf_id);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = pdf.filename || 'signed.pdf';
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      showMessage(`Tải xuống thành công: ${pdf.filename}`, 'success');
    } catch (err) {
      console.error('Error downloading PDF:', err);
      showMessage(`Lỗi tải xuống: ${err.message || err}`, 'error');
    } finally {
      setDownloading(null);
    }
  };

  const formatDate = (isoString) => {
    const date = new Date(isoString);
    return date.toLocaleString('vi-VN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  const getExpiryTime = (createdAt) => {
    const created = new Date(createdAt);
    const expiry = new Date(created.getTime() + 3600000); // 1 giờ = 3600000 ms
    return expiry.toLocaleString('vi-VN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  if (loading) {
    return (
      <div className="signed-pdfs-container">
        <div className="signed-pdfs-loader">Đang tải danh sách PDF...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="signed-pdfs-container">
        <div className="signed-pdfs-error">{error}</div>
      </div>
    );
  }

  if (pdfs.length === 0) {
    return (
      <div className="signed-pdfs-container">
        <div className="signed-pdfs-empty">
          <FileText size={48} className="signed-pdfs-empty-icon" />
          <p>Chưa có PDF nào được ký</p>
          <small>Ký một PDF để có trong danh sách</small>
        </div>
      </div>
    );
  }

  return (
    <div className="signed-pdfs-container">
      <div className="signed-pdfs-header">
        <h3 className="signed-pdfs-title">Lịch sử PDF đã ký</h3>
        <span className="signed-pdfs-count">{pdfs.length} PDF</span>
      </div>

      <div className="signed-pdfs-list">
        {pdfs.map((pdf) => {
          const remaining = pdf.remaining_seconds ?? 3600;
          const isExpired = remaining <= 0;
          const expiryTime = getExpiryTime(pdf.created_at);
          
          return (
            <div key={pdf.pdf_id} className={`signed-pdf-item ${isExpired ? 'expired' : ''}`}>
              <div className="signed-pdf-info">
                <div className="signed-pdf-main">
                  <FileText size={20} className="signed-pdf-icon" />
                  <div className="signed-pdf-details">
                    <div className="signed-pdf-name">{pdf.filename}</div>
                    <div className="signed-pdf-time">
                      <Clock size={14} />
                      <span>{formatDate(pdf.signed_at)}</span>
                    </div>
                  </div>
                </div>
                
                {/* Expiry Time Display */}
                <div className={`signed-pdf-expiry ${isExpired ? 'expired' : 'active'}`}>
                  <div className="expiry-label">Hết hạn lúc:</div>
                  <div className="expiry-time">{expiryTime}</div>
                </div>
                
                {isExpired && (
                  <div className="signed-pdf-badge expired-badge">Hết hạn</div>
                )}
                {pdf.is_cached && !isExpired && (
                  <div className="signed-pdf-badge active-badge">Còn hạn</div>
                )}
              </div>

              <div className="signed-pdf-actions">
                <button
                  className="signed-pdf-btn signed-pdf-btn-download"
                  onClick={() => handleDownload(pdf)}
                  disabled={downloading === pdf.pdf_id || isExpired}
                  title={isExpired ? 'PDF đã hết hạn' : 'Tải xuống'}
                >
                  <Download size={16} />
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
