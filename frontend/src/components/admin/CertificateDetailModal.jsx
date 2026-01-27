import React from 'react';
import {
  X,
  Award,
  User,
  Calendar,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Key,
  RotateCcw,
  Ban
} from 'lucide-react';
import '../../static/styles/admin.css';

/**
 * CertificateDetailModal Component
 * 
 * Shows detailed certificate information
 */
export default function CertificateDetailModal({ certificate, onClose, onRenew, onRevoke }) {
  const formatDate = (dateStr) => {
    if (!dateStr) return '-';
    return new Date(dateStr).toLocaleString('vi-VN', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getStatusIcon = () => {
    switch (certificate.status) {
      case 'active':
        return <CheckCircle size={20} />;
      case 'revoked':
        return <XCircle size={20} />;
      case 'expired':
        return <XCircle size={20} />;
      case 'expiring':
        return <AlertTriangle size={20} />;
      default:
        return <Clock size={20} />;
    }
  };

  const getStatusLabel = () => {
    switch (certificate.status) {
      case 'active':
        return 'Hợp lệ';
      case 'revoked':
        return 'Thu hồi';
      case 'expired':
        return 'Hết hạn';
      case 'expiring':
        return 'Sắp hết hạn';
      default:
        return certificate.status;
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content cert-detail-modal" onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="modal-header">
          <div className="cert-header-info">
            <div className={`cert-icon ${certificate.status}`}>
              <Award size={28} />
            </div>
            <div>
              <h2>{certificate.common_name || 'Certificate'}</h2>
              <span className={`status-badge large ${certificate.status}`}>
                {getStatusIcon()}
                {getStatusLabel()}
              </span>
            </div>
          </div>
          <button className="btn-close" onClick={onClose}>
            <X size={20} />
          </button>
        </div>

        {/* Content */}
        <div className="modal-body">
          {/* Owner Info */}
          <div className="detail-section">
            <h3>
              <User size={18} />
              Chủ sở hữu
            </h3>
            <div className="detail-grid">
              <div className="detail-item">
                <span className="label">Tên đăng nhập:</span>
                <span className="value">{certificate.username}</span>
              </div>
              <div className="detail-item">
                <span className="label">Họ tên:</span>
                <span className="value">{certificate.full_name || '-'}</span>
              </div>
            </div>
          </div>

          {/* Certificate Info */}
          <div className="detail-section">
            <h3>
              <Award size={18} />
              Thông tin chứng chỉ
            </h3>
            <div className="detail-grid">
              <div className="detail-item full-width">
                <span className="label">Tên chứng chỉ (CN):</span>
                <span className="value">{certificate.common_name || '-'}</span>
              </div>
              <div className="detail-item full-width">
                <Key size={16} />
                <span className="label">Số sê-ri:</span>
                <code className="serial-number">{certificate.serial_number || '-'}</code>
              </div>
            </div>
          </div>

          {/* Validity Period */}
          <div className="detail-section">
            <h3>
              <Calendar size={18} />
              Thời hạn hiệu lực
            </h3>
            <div className="detail-grid">
              <div className="detail-item">
                <span className="label">Ngày tạo:</span>
                <span className="value">{formatDate(certificate.created_at)}</span>
              </div>
              <div className="detail-item">
                <span className="label">Có hiệu lực từ:</span>
                <span className="value">{formatDate(certificate.valid_from)}</span>
              </div>
              <div className="detail-item">
                <span className="label">Hết hạn:</span>
                <span className="value">{formatDate(certificate.expires_at)}</span>
              </div>
              <div className="detail-item">
                <span className="label">Thời gian còn lại:</span>
                <span className={`days-badge ${certificate.days_remaining <= 30 ? 'warning' : ''}`}>
                  {certificate.status === 'revoked' 
                    ? '-' 
                    : certificate.days_remaining > 0 
                      ? `${certificate.days_remaining} ngày`
                      : 'Hết hạn'}
                </span>
              </div>
            </div>
          </div>

          {/* Revocation Info (if revoked) */}
          {certificate.status === 'revoked' && (
            <div className="detail-section revoked-section">
              <h3>
                <XCircle size={18} />
                Thông tin thu hồi
              </h3>
              <div className="detail-grid">
                <div className="detail-item">
                  <span className="label">Ngày thu hồi:</span>
                  <span className="value">{formatDate(certificate.revoked_at)}</span>
                </div>
                <div className="detail-item">
                  <span className="label">Thu hồi bởi:</span>
                  <span className="value">{certificate.revoked_by || '-'}</span>
                </div>
                <div className="detail-item full-width">
                  <span className="label">Lý do:</span>
                  <span className="value">{certificate.revocation_reason || 'Không xác định'}</span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="modal-footer">
          {certificate.active && (
            <>
              <button className="btn-secondary" onClick={onRenew}>
                <RotateCcw size={16} />
                Gia hạn
              </button>
              <button className="btn-danger" onClick={onRevoke}>
                <Ban size={16} />
                Thu hồi
              </button>
            </>
          )}
          <button className="btn-cancel" onClick={onClose}>
            Đóng
          </button>
        </div>
      </div>
    </div>
  );
}
