import React from 'react';
import {
  X,
  FileText,
  User,
  Calendar,
  Clock,
  CheckCircle,
  XCircle,
  Award,
  Hash,
  MapPin,
  Ban
} from 'lucide-react';
import '../../static/styles/admin.css';

/**
 * SignatureDetailModal Component
 * 
 * Shows detailed signature information
 */
export default function SignatureDetailModal({ signature, onClose, onRevoke }) {
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

  const formatFileSize = (bytes) => {
    if (!bytes) return '-';
    const kb = bytes / 1024;
    if (kb < 1024) return `${kb.toFixed(1)} KB`;
    return `${(kb / 1024).toFixed(2)} MB`;
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content signature-detail-modal" onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="modal-header">
          <div className="signature-header-info">
            <div className={`signature-icon ${signature.status}`}>
              <FileText size={28} />
            </div>
            <div>
              <h2 title={signature.document_name}>
                {signature.document_name?.length > 40 
                  ? signature.document_name.substring(0, 40) + '...'
                  : signature.document_name || 'Document'}
              </h2>
              <span className={`status-badge large ${signature.status}`}>
                {signature.status === 'valid' ? (
                  <>
                    <CheckCircle size={16} />
                    Hợp lệ
                  </>
                ) : (
                  <>
                    <XCircle size={16} />
                    Thu hồi
                  </>
                )}
              </span>
            </div>
          </div>
          <button className="btn-close" onClick={onClose}>
            <X size={20} />
          </button>
        </div>

        {/* Content */}
        <div className="modal-body">
          {/* Document Info */}
          <div className="detail-section">
            <h3>
              <FileText size={18} />
              Thông tin tài liệu
            </h3>
            <div className="detail-grid">
              <div className="detail-item full-width">
                <span className="label">Tên file:</span>
                <span className="value">{signature.document_name || '-'}</span>
              </div>
              <div className="detail-item">
                <span className="label">Kích thước:</span>
                <span className="value">{formatFileSize(signature.document_size)}</span>
              </div>
              <div className="detail-item full-width">
                <Hash size={16} />
                <span className="label">Hash (SHA-256):</span>
                <code className="hash-value">{signature.document_hash || '-'}</code>
              </div>
            </div>
          </div>

          {/* Signer Info */}
          <div className="detail-section">
            <h3>
              <User size={18} />
              Người ký
            </h3>
            <div className="detail-grid">
              <div className="detail-item">
                <span className="label">Tên đăng nhập:</span>
                <span className="value">{signature.user || '-'}</span>
              </div>
              <div className="detail-item">
                <Award size={16} />
                <span className="label">Chứng chỉ:</span>
                <span className={`cert-badge ${signature.certificate_active ? 'active' : 'revoked'}`}>
                  {signature.certificate_cn || '-'}
                </span>
              </div>
            </div>
          </div>

          {/* Signing Details */}
          <div className="detail-section">
            <h3>
              <Calendar size={18} />
              Chi tiết ký số
            </h3>
            <div className="detail-grid">
              <div className="detail-item">
                <Clock size={16} />
                <span className="label">Thời gian ký:</span>
                <span className="value">{formatDate(signature.signed_at)}</span>
              </div>
              <div className="detail-item">
                <MapPin size={16} />
                <span className="label">Vị trí:</span>
                <span className="value">{signature.location || '-'}</span>
              </div>
              <div className="detail-item full-width">
                <span className="label">Lý do ký:</span>
                <span className="value">{signature.reason || '-'}</span>
              </div>
            </div>
          </div>

          {/* Revocation Info (if revoked) */}
          {signature.status === 'revoked' && (
            <div className="detail-section revoked-section">
              <h3>
                <XCircle size={18} />
                Thông tin thu hồi
              </h3>
              <div className="detail-grid">
                <div className="detail-item">
                  <span className="label">Ngày thu hồi:</span>
                  <span className="value">{formatDate(signature.revoked_at)}</span>
                </div>
                <div className="detail-item">
                  <span className="label">Thu hồi bởi:</span>
                  <span className="value">{signature.revoked_by || '-'}</span>
                </div>
                <div className="detail-item full-width">
                  <span className="label">Lý do:</span>
                  <span className="value">{signature.revocation_reason || 'Không xác định'}</span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="modal-footer">
          {signature.status === 'valid' && (
            <button className="btn-danger" onClick={onRevoke}>
              <Ban size={16} />
              Thu hồi chữ ký
            </button>
          )}
          <button className="btn-cancel" onClick={onClose}>
            Đóng
          </button>
        </div>
      </div>
    </div>
  );
}
