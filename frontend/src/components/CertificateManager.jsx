import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  Shield,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Clock,
  Download,
  RefreshCw,
  Calendar,
  Key,
  FileKey,
  Award,
  Info
} from 'lucide-react';
import { getCertificateInfo, downloadCertificate, renewCertificate } from '../api';
import '../static/styles/certificate-manager.css';

/**
 * CertificateManager Component
 * 
 * Displays certificate information and management options:
 * - Current certificate status
 * - Expiration date and days remaining
 * - Certificate details (CN, serial, issuer)
 * - Download options (P12, PEM)
 * - Renewal option (if near expiration)
 */
export default function CertificateManager({ username }) {
  const navigate = useNavigate();
  const [certInfo, setCertInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [downloadLoading, setDownloadLoading] = useState(false);
  const [renewLoading, setRenewLoading] = useState(false);
  const [message, setMessage] = useState(null);

  useEffect(() => {
    loadCertificateInfo();
  }, [username]);

  const loadCertificateInfo = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await getCertificateInfo();
      setCertInfo(data);
    } catch (err) {
      setError('Không thể tải thông tin chứng chỉ: ' + (err.message || err));
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async (format) => {
    try {
      setDownloadLoading(true);
      const blob = await downloadCertificate(format);
      
      // Create download link
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `certificate.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
      setMessage({ type: 'success', text: 'Tải chứng chỉ thành công!' });
    } catch (err) {
      setMessage({ type: 'error', text: 'Lỗi tải chứng chỉ: ' + (err.message || err) });
    } finally {
      setDownloadLoading(false);
    }
  };

  const handleRenew = async () => {
    if (!window.confirm('Bạn có chắc muốn gia hạn chứng chỉ? Chứng chỉ cũ sẽ bị thay thế.')) {
      return;
    }
    
    try {
      setRenewLoading(true);
      await renewCertificate();
      setMessage({ type: 'success', text: 'Gia hạn chứng chỉ thành công!' });
      loadCertificateInfo(); // Reload to show new cert
    } catch (err) {
      setMessage({ type: 'error', text: 'Lỗi gia hạn: ' + (err.message || err) });
    } finally {
      setRenewLoading(false);
    }
  };

  // Get status display
  const getStatusDisplay = () => {
    if (!certInfo) return null;

    const { status, daysUntilExpiry } = certInfo;

    if (status === 'revoked') {
      return {
        icon: XCircle,
        text: 'Đã thu hồi',
        description: 'Chứng chỉ đã bị thu hồi và không còn hiệu lực.',
        className: 'status-revoked',
        canRenew: true
      };
    }
    if (status === 'expired') {
      return {
        icon: XCircle,
        text: 'Hết hạn',
        description: 'Chứng chỉ đã hết hạn sử dụng.',
        className: 'status-expired',
        canRenew: true
      };
    }
    if (daysUntilExpiry !== null && daysUntilExpiry <= 30) {
      return {
        icon: AlertTriangle,
        text: 'Sắp hết hạn',
        description: `Chứng chỉ sẽ hết hạn trong ${daysUntilExpiry} ngày.`,
        className: 'status-warning',
        canRenew: true
      };
    }
    if (status === 'valid') {
      return {
        icon: CheckCircle,
        text: 'Hợp lệ',
        description: 'Chứng chỉ đang hoạt động bình thường.',
        className: 'status-valid',
        canRenew: daysUntilExpiry !== null && daysUntilExpiry <= 60
      };
    }
    return {
      icon: AlertTriangle,
      text: 'Không xác định',
      description: 'Không thể xác định trạng thái chứng chỉ.',
      className: 'status-unknown',
      canRenew: false
    };
  };

  const statusDisplay = getStatusDisplay();
  const StatusIcon = statusDisplay?.icon || AlertTriangle;

  // Format date
  const formatDate = (dateString) => {
    if (!dateString) return '-';
    return new Date(dateString).toLocaleDateString('vi-VN', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  return (
    <div className="cert-manager-container">
      {/* Header */}
      <div className="cert-header">
        <button className="back-button" onClick={() => navigate(-1)}>
          <ArrowLeft size={20} />
          Quay lại
        </button>
        <h1 className="cert-title">
          <Shield size={24} />
          Quản lý chứng chỉ
        </h1>
      </div>

      {/* Message */}
      {message && (
        <div className={`message-banner ${message.type}`}>
          {message.type === 'success' ? <CheckCircle size={18} /> : <AlertTriangle size={18} />}
          {message.text}
          <button onClick={() => setMessage(null)}>×</button>
        </div>
      )}

      {/* Content */}
      {loading ? (
        <div className="loading-state">
          <RefreshCw size={32} className="spinning" />
          <p>Đang tải thông tin chứng chỉ...</p>
        </div>
      ) : error ? (
        <div className="error-state">
          <AlertTriangle size={32} />
          <p>{error}</p>
          <button onClick={loadCertificateInfo}>Thử lại</button>
        </div>
      ) : !certInfo?.hasCertificate ? (
        <div className="no-cert-state">
          <FileKey size={48} />
          <h3>Chưa có chứng chỉ</h3>
          <p>Bạn chưa được cấp chứng chỉ số. Vui lòng liên hệ quản trị viên.</p>
        </div>
      ) : (
        <div className="cert-content">
          {/* Status Card */}
          <div className={`status-card ${statusDisplay?.className}`}>
            <div className="status-icon-large">
              <StatusIcon size={48} />
            </div>
            <div className="status-info">
              <h2>{statusDisplay?.text}</h2>
              <p>{statusDisplay?.description}</p>
            </div>
            {statusDisplay?.canRenew && (
              <button 
                className="renew-button"
                onClick={handleRenew}
                disabled={renewLoading}
              >
                {renewLoading ? <RefreshCw size={18} className="spinning" /> : <RefreshCw size={18} />}
                Gia hạn
              </button>
            )}
          </div>

          {/* Certificate Details */}
          <div className="cert-details-grid">
            <div className="detail-card">
              <div className="detail-icon">
                <Award size={24} />
              </div>
              <div className="detail-content">
                <span className="detail-label">Tên chủ thể (CN)</span>
                <span className="detail-value">{certInfo.commonName || '-'}</span>
              </div>
            </div>

            <div className="detail-card">
              <div className="detail-icon">
                <Key size={24} />
              </div>
              <div className="detail-content">
                <span className="detail-label">Số sê-ri</span>
                <span className="detail-value mono">{certInfo.serialNumber || '-'}</span>
              </div>
            </div>

            <div className="detail-card">
              <div className="detail-icon">
                <Shield size={24} />
              </div>
              <div className="detail-content">
                <span className="detail-label">Nhà phát hành</span>
                <span className="detail-value">{certInfo.issuer || 'Internal CA'}</span>
              </div>
            </div>

            <div className="detail-card">
              <div className="detail-icon">
                <Calendar size={24} />
              </div>
              <div className="detail-content">
                <span className="detail-label">Ngày cấp</span>
                <span className="detail-value">{formatDate(certInfo.createdAt)}</span>
              </div>
            </div>

            <div className="detail-card">
              <div className="detail-icon">
                <Clock size={24} />
              </div>
              <div className="detail-content">
                <span className="detail-label">Ngày hết hạn</span>
                <span className="detail-value">{formatDate(certInfo.expiresAt)}</span>
              </div>
            </div>

            <div className="detail-card">
              <div className="detail-icon">
                <Info size={24} />
              </div>
              <div className="detail-content">
                <span className="detail-label">Thời gian còn lại</span>
                <span className="detail-value">
                  {certInfo.daysUntilExpiry !== null 
                    ? `${certInfo.daysUntilExpiry} ngày`
                    : '-'
                  }
                </span>
              </div>
            </div>
          </div>

          {/* Download Section */}
          <div className="download-section">
            <h3>
              <Download size={20} />
              Tải chứng chỉ
            </h3>
            <div className="download-options">
              <button 
                className="download-btn"
                onClick={() => handleDownload('p12')}
                disabled={downloadLoading}
              >
                <FileKey size={20} />
                <span>PKCS#12 (.p12)</span>
                <small>Chứa khóa riêng tư</small>
              </button>
              <button 
                className="download-btn"
                onClick={() => handleDownload('pem')}
                disabled={downloadLoading}
              >
                <FileKey size={20} />
                <span>PEM Certificate</span>
                <small>Chỉ chứng chỉ công khai</small>
              </button>
              <button 
                className="download-btn"
                onClick={() => handleDownload('chain')}
                disabled={downloadLoading}
              >
                <Shield size={20} />
                <span>Certificate Chain</span>
                <small>Bao gồm CA chain</small>
              </button>
            </div>
          </div>

          {/* Fingerprint */}
          {certInfo.fingerprint && (
            <div className="fingerprint-section">
              <h3>
                <Key size={20} />
                SHA-256 Fingerprint
              </h3>
              <code className="fingerprint">{certInfo.fingerprint}</code>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
