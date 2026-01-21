import React, { useState, useRef, useEffect } from 'react';
import {
  Shield,
  PenTool,
  CheckCircle,
  LogIn,
  LogOut,
  User,
  Settings
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
  const [showDropdown, setShowDropdown] = useState(false);
  const dropdownRef = useRef(null);

  useEffect(() => {
    function handleClickOutside(event) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setShowDropdown(false);
      }
    }

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);
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
            <div 
              className="user-dropdown"
              ref={dropdownRef}
            >
              <button 
                className="user-profile-btn"
                onClick={() => setShowDropdown(!showDropdown)}
              >
                <div className="user-avatar">
                  {username.charAt(0).toUpperCase()}
                </div>
                <span className="user-name">{username}</span>
              </button>

              {showDropdown && (
                <div className="dropdown-menu">
                  <div className="dropdown-header">
                    <div className="dropdown-avatar-lg">
                      {username.charAt(0).toUpperCase()}
                    </div>
                    <div className="dropdown-user-info">
                      <div className="dropdown-username">{username}</div>
                      <div className="dropdown-user-sub">CA System</div>
                    </div>
                  </div>
                  <button
                    className="dropdown-item"
                    onClick={() => {
                      onEditProfile();
                      setShowDropdown(false);
                    }}
                  >
                    <Settings size={16} />
                    <span>Chỉnh sửa thông tin</span>
                  </button>
                  <button
                    className="dropdown-item logout-item"
                    onClick={() => {
                      onLogout();
                      setShowDropdown(false);
                    }}
                  >
                    <LogOut size={16} />
                    <span>Đăng xuất</span>
                  </button>
                </div>
              )}
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
