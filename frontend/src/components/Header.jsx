import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  Shield,
  PenTool,
  CheckCircle,
  LogIn
} from 'lucide-react';
import UserDropdown from './UserDropdown';
import '../static/styles/header.css';
import '../static/styles/dropdown.css';

/**
 * Header Component with React Router Navigation
 * Uses useNavigate for SPA routing (no page reload)
 * Uses useLocation to highlight active tab
 */
export default function Header({
  user,
  onAuthClick,
  onLogout,
  certificateInfo,
  signingStats
}) {
  const navigate = useNavigate();
  const location = useLocation();
  
  // Determine active tab from current route
  const isSignActive = location.pathname === '/sign' || location.pathname === '/';
  const isVerifyActive = location.pathname === '/verify';
  
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
            className={`nav-tab ${isSignActive ? 'active' : ''}`}
            onClick={() => navigate('/sign')}
          >
            <PenTool size={18} />
            Ký số
          </button>
          <button
            className={`nav-tab ${isVerifyActive ? 'active' : ''}`}
            onClick={() => navigate('/verify')}
          >
            <CheckCircle size={18} />
            Xác thực
          </button>
        </nav>

        <div className="header-user">
          {user ? (
            <UserDropdown 
              user={user}
              onLogout={onLogout}
              certificateInfo={certificateInfo}
              signingStats={signingStats}
            />
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
