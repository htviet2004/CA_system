import React, { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  User,
  LogOut,
  FileText,
  Shield,
  Settings,
  ChevronDown,
  Key,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  Award
} from 'lucide-react';
import '../static/styles/dropdown.css';

/**
 * UserDropdown Component
 * 
 * Displays a dropdown menu for authenticated users with:
 * - Profile management
 * - Signing history
 * - Certificate status
 * - Logout
 * 
 * Features:
 * - Click outside to close
 * - Keyboard navigation (Escape to close)
 * - Role-aware rendering
 * - Accessibility support
 */
export default function UserDropdown({ 
  user, 
  onLogout,
  certificateInfo
}) {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef(null);
  const navigate = useNavigate();

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    };

    const handleEscape = (event) => {
      if (event.key === 'Escape') {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      document.addEventListener('keydown', handleEscape);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleEscape);
    };
  }, [isOpen]);

  const toggleDropdown = () => {
    setIsOpen(!isOpen);
  };

  const handleMenuClick = (action) => {
    setIsOpen(false);
    action();
  };

  // Get certificate status badge
  const getCertStatusBadge = () => {
    if (!certificateInfo) {
      return { icon: AlertTriangle, text: 'Không có', className: 'status-none' };
    }

    const { status, days_remaining } = certificateInfo;

    if (status === 'revoked') {
      return { icon: XCircle, text: 'Đã thu hồi', className: 'status-revoked' };
    }
    if (status === 'expired') {
      return { icon: XCircle, text: 'Hết hạn', className: 'status-expired' };
    }
    if (days_remaining !== null && days_remaining <= 30) {
      return { icon: AlertTriangle, text: `Còn ${days_remaining} ngày`, className: 'status-warning' };
    }
    if (status === 'valid') {
      return { icon: CheckCircle, text: 'Hợp lệ', className: 'status-valid' };
    }
    return { icon: AlertTriangle, text: 'Không xác định', className: 'status-unknown' };
  };

  const certBadge = getCertStatusBadge();
  const CertIcon = certBadge.icon;

  return (
    <div className="user-dropdown" ref={dropdownRef}>
      {/* Trigger Button */}
      <button 
        className={`dropdown-trigger ${isOpen ? 'active' : ''}`}
        onClick={toggleDropdown}
        aria-expanded={isOpen}
        aria-haspopup="true"
      >
        <div className="user-avatar">
          {user.username.charAt(0).toUpperCase()}
        </div>
        <div className="user-info-text">
          <span className="user-name">{user.username}</span>
          {user.is_staff && <span className="user-role">Admin</span>}
        </div>
        <ChevronDown 
          size={16} 
          className={`dropdown-arrow ${isOpen ? 'rotated' : ''}`} 
        />
      </button>

      {/* Dropdown Menu */}
      {isOpen && (
        <div className="dropdown-menu" role="menu">
          {/* User Header */}
          <div className="dropdown-header">
            <div className="dropdown-avatar">
              {user.username.charAt(0).toUpperCase()}
            </div>
            <div className="dropdown-user-info">
              <span className="dropdown-username">{user.username}</span>
              <span className="dropdown-role">
                {user.is_staff ? 'Quản trị viên' : 'Người dùng'}
              </span>
            </div>
          </div>

          <div className="dropdown-divider" />

          {/* Certificate Status Card */}
          <div className="dropdown-section">
            <div className="section-title">
              <Award size={14} />
              Chứng chỉ số
            </div>
            <div className={`cert-status-card ${certBadge.className}`}>
              <div className="cert-status-icon">
                <CertIcon size={20} />
              </div>
              <div className="cert-status-info">
                <span className="cert-status-label">Trạng thái</span>
                <span className="cert-status-value">{certBadge.text}</span>
              </div>
              {certificateInfo?.expires_at && (
                <div className="cert-expiry">
                  <Clock size={12} />
                  <span>{new Date(certificateInfo.expires_at).toLocaleDateString('vi-VN')}</span>
                </div>
              )}
            </div>
          </div>

          <div className="dropdown-divider" />

          {/* Menu Items */}
          <div className="dropdown-items">
            <button 
              className="dropdown-item"
              onClick={() => handleMenuClick(() => navigate('/profile'))}
              role="menuitem"
            >
              <User size={18} />
              <span>Thông tin cá nhân</span>
            </button>

            <button 
              className="dropdown-item"
              onClick={() => handleMenuClick(() => navigate('/signing-history'))}
              role="menuitem"
            >
              <FileText size={18} />
              <span>Lịch sử ký số</span>
            </button>

            <button 
              className="dropdown-item"
              onClick={() => handleMenuClick(() => navigate('/certificates'))}
              role="menuitem"
            >
              <Shield size={18} />
              <span>Quản lý chứng chỉ</span>
            </button>

            {/* Admin-only items */}
            {user.is_staff && (
              <>
                <div className="dropdown-divider" />
                <button 
                  className="dropdown-item admin-item"
                  onClick={() => handleMenuClick(() => navigate('/admin'))}
                  role="menuitem"
                >
                  <Settings size={18} />
                  <span>Bảng điều khiển Admin</span>
                </button>
              </>
            )}

            <div className="dropdown-divider" />

            <button 
              className="dropdown-item"
              onClick={() => handleMenuClick(() => navigate('/change-password'))}
              role="menuitem"
            >
              <Key size={18} />
              <span>Đổi mật khẩu</span>
            </button>

            <button 
              className="dropdown-item logout-item"
              onClick={() => handleMenuClick(onLogout)}
              role="menuitem"
            >
              <LogOut size={18} />
              <span>Đăng xuất</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
