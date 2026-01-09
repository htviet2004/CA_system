import React from 'react';
import {
  Shield,
  PenTool,
  CheckCircle,
  LogIn,
  LogOut,
  User
} from 'lucide-react';
import '../static/styles/header.css';

export default function Header({
  username,
  activeTab,
  onTabChange,
  onAuthClick,
  onLogout,
  onEditProfile
}) {
  return (
    <header className="header">
      <div className="header-content">
        <div className="header-brand">
          <div className="header-logo">
            <Shield size={32} color="#ffffff" />
          </div>
          <div className="header-text">
            <h1 className="header-title">CA System</h1>
            <p className="header-subtitle">PDF Signing & Verification</p>
          </div>
        </div>

        <nav className="header-nav">
          <button
            className={`nav-tab ${activeTab === 'sign' ? 'active' : ''}`}
            onClick={() => onTabChange('sign')}
          >
            <PenTool size={18} />
            Ký số
          </button>
          <button
            className={`nav-tab ${activeTab === 'verify' ? 'active' : ''}`}
            onClick={() => onTabChange('verify')}
          >
            <CheckCircle size={18} />
            Xác thực
          </button>
        </nav>

        <div className="header-user">
          {username ? (
            <div className="user-info">
              <button
                className="btn-profile"
                onClick={onEditProfile}
                title="Chỉnh sửa thông tin"
              >
                <User size={18} />
              </button>

              <div className="user-avatar">
                {username.charAt(0).toUpperCase()}
              </div>
              <span className="user-name">{username}</span>

              <button
                className="btn-logout"
                onClick={onLogout}
                title="Đăng xuất"
              >
                <LogOut size={18} />
              </button>
            </div>
          ) : (
            <button className="btn-login" onClick={onAuthClick}>
              <LogIn size={18} />
              Đăng nhập
            </button>
          )}
        </div>
      </div>
    </header>
  );
}
