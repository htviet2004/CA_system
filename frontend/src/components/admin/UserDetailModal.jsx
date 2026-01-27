import React from 'react';
import {
  X,
  User,
  Mail,
  Phone,
  Building,
  Calendar,
  Clock,
  Shield,
  Award,
  Edit,
  RefreshCw,
  CheckCircle,
  XCircle
} from 'lucide-react';
import '../../static/styles/admin.css';

/**
 * UserDetailModal Component
 * 
 * Shows detailed user information including:
 * - Account info
 * - Profile data
 * - Certificates
 * - Actions (edit, reissue cert)
 */
export default function UserDetailModal({ user, onClose, onEdit, onReissueCert }) {
  const userData = user?.user || {};
  const profile = user?.profile || {};
  const certificates = user?.certificates || [];
  
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

  const handleReissueCert = () => {
    if (window.confirm(`Cấp lại chứng chỉ cho ${userData.username}?`)) {
      onReissueCert(userData.id, profile.full_name || userData.username);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content user-detail-modal" onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="modal-header">
          <div className="user-header-info">
            <div className="user-avatar large">
              {userData.username?.charAt(0).toUpperCase() || '?'}
            </div>
            <div>
              <h2>
                {profile.full_name || userData.username}
                {userData.is_staff && <Shield size={18} className="admin-badge" title="Admin" />}
              </h2>
              <span className="username">@{userData.username}</span>
            </div>
          </div>
          <button className="btn-close" onClick={onClose}>
            <X size={20} />
          </button>
        </div>

        {/* Content */}
        <div className="modal-body">
          {/* Account Status */}
          <div className="detail-section">
            <h3>Trạng thái tài khoản</h3>
            <div className="status-row">
              <span className={`status-badge large ${userData.is_active ? 'active' : 'inactive'}`}>
                {userData.is_active ? (
                  <>
                    <CheckCircle size={16} />
                    Đang hoạt động
                  </>
                ) : (
                  <>
                    <XCircle size={16} />
                    Đã khóa
                  </>
                )}
              </span>
              {userData.is_staff && (
                <span className="role-badge admin">
                  <Shield size={14} />
                  Administrator
                </span>
              )}
            </div>
          </div>

          {/* Account Info */}
          <div className="detail-section">
            <h3>Thông tin tài khoản</h3>
            <div className="detail-grid">
              <div className="detail-item">
                <User size={16} />
                <span className="label">Tên đăng nhập:</span>
                <span className="value">{userData.username}</span>
              </div>
              <div className="detail-item">
                <Mail size={16} />
                <span className="label">Email:</span>
                <span className="value">{userData.email || profile.email || '-'}</span>
              </div>
              <div className="detail-item">
                <Calendar size={16} />
                <span className="label">Ngày tạo:</span>
                <span className="value">{formatDate(userData.date_joined)}</span>
              </div>
              <div className="detail-item">
                <Clock size={16} />
                <span className="label">Đăng nhập cuối:</span>
                <span className="value">{formatDate(userData.last_login)}</span>
              </div>
            </div>
          </div>

          {/* Profile Info */}
          <div className="detail-section">
            <h3>Thông tin cá nhân</h3>
            <div className="detail-grid">
              <div className="detail-item">
                <User size={16} />
                <span className="label">Họ và tên:</span>
                <span className="value">{profile.full_name || '-'}</span>
              </div>
              <div className="detail-item">
                <Phone size={16} />
                <span className="label">Điện thoại:</span>
                <span className="value">{profile.phone || '-'}</span>
              </div>
              <div className="detail-item">
                <Shield size={16} />
                <span className="label">Vai trò:</span>
                <span className={`role-badge ${profile.role || 'student'}`}>
                  {profile.role_display || 'Student'}
                </span>
              </div>
              <div className="detail-item">
                <Building size={16} />
                <span className="label">Khoa/Phòng:</span>
                <span className="value">{profile.department_display || '-'}</span>
              </div>
            </div>
            {profile.notes && (
              <div className="notes-section">
                <span className="label">Ghi chú:</span>
                <p className="notes-text">{profile.notes}</p>
              </div>
            )}
          </div>

          {/* Certificates */}
          <div className="detail-section">
            <h3>
              <Award size={18} />
              Chứng chỉ số ({certificates.length})
            </h3>
            {certificates.length > 0 ? (
              <div className="certificates-list">
                {certificates.map(cert => (
                  <div key={cert.id} className={`cert-card ${cert.active ? 'active' : 'revoked'}`}>
                    <div className="cert-header">
                      <span className="cert-cn">{cert.common_name}</span>
                      <span className={`cert-status ${cert.active ? 'active' : 'revoked'}`}>
                        {cert.active ? 'Hợp lệ' : 'Thu hồi'}
                      </span>
                    </div>
                    <div className="cert-details">
                      <span>Serial: {cert.serial_number?.substring(0, 16)}...</span>
                      <span>Tạo: {formatDate(cert.created_at)}</span>
                      <span>Hết hạn: {formatDate(cert.expires_at)}</span>
                    </div>
                    {cert.revoked_at && (
                      <div className="cert-revoked-info">
                        Thu hồi: {formatDate(cert.revoked_at)} - {cert.revocation_reason}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <p className="no-data">Chưa có chứng chỉ</p>
            )}
          </div>

          {/* Signing Stats */}
          <div className="detail-section">
            <h3>Thống kê ký số</h3>
            <div className="signing-stats">
              <span className="stat">
                Tổng số lượt ký: <strong>{user?.signing_count || 0}</strong>
              </span>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="modal-footer">
          <button className="btn-secondary" onClick={handleReissueCert}>
            <RefreshCw size={16} />
            Cấp lại chứng chỉ
          </button>
          <button className="btn-primary" onClick={onEdit}>
            <Edit size={16} />
            Chỉnh sửa
          </button>
        </div>
      </div>
    </div>
  );
}
