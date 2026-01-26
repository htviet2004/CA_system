import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  ArrowLeft,
  FileText,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Clock,
  Download,
  RefreshCw,
  Calendar,
  Shield,
  Hash,
  Globe,
  Monitor,
  User,
  Info
} from 'lucide-react';
import { getSignedDocumentDetail, downloadSignedDocument } from '../api';
import '../static/styles/signing-history.css';

/**
 * SigningHistoryDetail Component
 * 
 * Displays detailed information about a single signed document including:
 * - Document metadata
 * - Certificate information
 * - Signature details
 * - Download option
 */
export default function SigningHistoryDetail({ showMessage }) {
  const navigate = useNavigate();
  const { documentId } = useParams();
  const [document, setDocument] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [downloading, setDownloading] = useState(false);

  useEffect(() => {
    loadDocument();
  }, [documentId]);

  const loadDocument = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await getSignedDocumentDetail(documentId);
      setDocument(data);
    } catch (err) {
      setError(err.message || 'Không thể tải thông tin tài liệu');
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async () => {
    if (!document?.is_downloadable) {
      showMessage?.('Tài liệu này không còn khả dụng để tải xuống', 'error');
      return;
    }

    try {
      setDownloading(true);
      const blob = await downloadSignedDocument(documentId);
      
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = document.document_name.replace('.pdf', '_signed.pdf');
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);

      showMessage?.('Tải xuống thành công!', 'success');
      loadDocument(); // Refresh to update download count
    } catch (err) {
      showMessage?.('Lỗi tải xuống: ' + (err.message || err), 'error');
    } finally {
      setDownloading(false);
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return '-';
    const date = new Date(dateString);
    return date.toLocaleString('vi-VN', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  const formatSize = (bytes) => {
    if (!bytes) return '-';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  };

  const StatusBadge = ({ status }) => {
    const config = {
      valid: { icon: CheckCircle, text: 'Hợp lệ', className: 'status-valid' },
      revoked: { icon: XCircle, text: 'Đã thu hồi', className: 'status-revoked' },
      expired: { icon: AlertTriangle, text: 'Hết hạn', className: 'status-expired' },
      deleted: { icon: XCircle, text: 'Đã xóa', className: 'status-deleted' },
      invalid: { icon: XCircle, text: 'Không hợp lệ', className: 'status-invalid' }
    };

    const { icon: Icon, text, className } = config[status] || config.invalid;

    return (
      <span className={`status-badge ${className}`}>
        <Icon size={16} />
        {text}
      </span>
    );
  };

  if (loading) {
    return (
      <div className="signing-history-container">
        <div className="loading-state">
          <RefreshCw size={32} className="spinning" />
          <p>Đang tải thông tin tài liệu...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="signing-history-container">
        <div className="history-header">
          <button className="back-button" onClick={() => navigate('/signing-history')}>
            <ArrowLeft size={20} />
            Quay lại
          </button>
        </div>
        <div className="error-state">
          <AlertTriangle size={32} />
          <p>{error}</p>
          <button onClick={loadDocument}>Thử lại</button>
        </div>
      </div>
    );
  }

  return (
    <div className="signing-history-container">
      {/* Header */}
      <div className="history-header">
        <button className="back-button" onClick={() => navigate('/signing-history')}>
          <ArrowLeft size={20} />
          Quay lại
        </button>
        <h1 className="history-title">
          <FileText size={24} />
          Chi tiết tài liệu
        </h1>
      </div>

      {/* Document Detail Card */}
      <div className="detail-card">
        {/* Document Header */}
        <div className="detail-header">
          <div className="detail-icon">
            <FileText size={32} />
          </div>
          <div className="detail-title-section">
            <h2 className="detail-doc-name">{document.document_name}</h2>
            <div className="detail-meta">
              <StatusBadge status={document.status} />
              <span className="detail-size">{formatSize(document.document_size)}</span>
            </div>
          </div>
          {document.is_downloadable && (
            <button 
              className="download-button"
              onClick={handleDownload}
              disabled={downloading}
            >
              {downloading ? (
                <RefreshCw size={18} className="spinning" />
              ) : (
                <Download size={18} />
              )}
              Tải xuống
            </button>
          )}
        </div>

        {/* Info Sections */}
        <div className="detail-sections">
          {/* Signing Info */}
          <div className="detail-section">
            <h3 className="section-title">
              <Calendar size={18} />
              Thông tin ký số
            </h3>
            <div className="info-grid">
              <div className="info-item">
                <span className="info-label">Thời gian ký</span>
                <span className="info-value">{formatDate(document.signed_at)}</span>
              </div>
              <div className="info-item">
                <span className="info-label">Lý do ký</span>
                <span className="info-value">{document.reason || '-'}</span>
              </div>
            </div>
          </div>

          {/* Certificate Info */}
          <div className="detail-section">
            <h3 className="section-title">
              <Shield size={18} />
              Thông tin chứng chỉ
            </h3>
            <div className="info-grid">
              <div className="info-item">
                <span className="info-label">Chủ thể (CN)</span>
                <span className="info-value">{document.certificate_cn || '-'}</span>
              </div>
              <div className="info-item">
                <span className="info-label">Serial Number</span>
                <span className="info-value mono">{document.certificate_serial || '-'}</span>
              </div>
            </div>
          </div>

          {/* Document Hash */}
          <div className="detail-section">
            <h3 className="section-title">
              <Hash size={18} />
              Hash tài liệu (SHA-256)
            </h3>
            <div className="hash-display">
              <code>{document.document_hash || '-'}</code>
            </div>
          </div>

          {/* Download Info */}
          {document.file_path && (
            <div className="detail-section">
              <h3 className="section-title">
                <Download size={18} />
                Thông tin lưu trữ
              </h3>
              <div className="info-grid">
                <div className="info-item">
                  <span className="info-label">Hết hạn lưu trữ</span>
                  <span className="info-value">
                    {formatDate(document.expires_at)}
                    {document.is_downloadable ? (
                      <span className="badge-inline success">Còn hiệu lực</span>
                    ) : (
                      <span className="badge-inline danger">Đã hết hạn</span>
                    )}
                  </span>
                </div>
                <div className="info-item">
                  <span className="info-label">Số lần tải</span>
                  <span className="info-value">{document.download_count || 0}</span>
                </div>
                {document.last_downloaded_at && (
                  <div className="info-item">
                    <span className="info-label">Lần tải cuối</span>
                    <span className="info-value">{formatDate(document.last_downloaded_at)}</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Client Info */}
          <div className="detail-section">
            <h3 className="section-title">
              <Monitor size={18} />
              Thông tin thiết bị
            </h3>
            <div className="info-grid">
              <div className="info-item">
                <span className="info-label">Địa chỉ IP</span>
                <span className="info-value mono">{document.ip_address || '-'}</span>
              </div>
              <div className="info-item full-width">
                <span className="info-label">User Agent</span>
                <span className="info-value small">{document.user_agent || '-'}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Warning for expiring documents */}
        {document.is_downloadable && document.expires_at && (
          <div className="expiry-warning">
            <Clock size={16} />
            <span>
              Tài liệu này sẽ hết hạn lưu trữ vào {formatDate(document.expires_at)}. 
              Vui lòng tải xuống trước thời hạn.
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
