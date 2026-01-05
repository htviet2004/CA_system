import React, { useState } from 'react';
import { UserPlus, LogIn, Eye, EyeOff, X } from 'lucide-react';
import '../static/styles/auth.css';

export default function AuthForm({ onRegister, onLogin, onClose }) {
  const [activeTab, setActiveTab] = useState('login');
  const [showPassword, setShowPassword] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    const username = e.target.username.value;
    const password = e.target.password.value;
    
    if (activeTab === 'register') {
      onRegister(e);
    } else {
      onLogin(e);
    }
  };

  return (
    <div className="auth-modal-card">
      <button className="modal-close" onClick={onClose}>
        <X size={24} />
      </button>

      <div className="auth-modal-header">
        <h2>{activeTab === 'login' ? 'Đăng nhập' : 'Đăng ký tài khoản'}</h2>
        <p>Vui lòng {activeTab === 'login' ? 'đăng nhập' : 'tạo tài khoản'} để sử dụng dịch vụ ký số</p>
      </div>

      <div className="auth-tabs">
        <button
          className={`auth-tab ${activeTab === 'login' ? 'active' : ''}`}
          onClick={() => setActiveTab('login')}
        >
          <LogIn size={18} />
          Đăng nhập
        </button>
        <button
          className={`auth-tab ${activeTab === 'register' ? 'active' : ''}`}
          onClick={() => setActiveTab('register')}
        >
          <UserPlus size={18} />
          Đăng ký
        </button>
      </div>

      <form className="auth-form" onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="username">Tên đăng nhập</label>
          <input
            type="text"
            id="username"
            name="username"
            placeholder="Nhập tên đăng nhập"
            required
          />
        </div>

        <div className="form-group">
          <label htmlFor="password">Mật khẩu</label>
          <div className="password-input">
            <input
              type={showPassword ? 'text' : 'password'}
              id="password"
              name="password"
              placeholder="Nhập mật khẩu"
              required
            />
            <button
              type="button"
              className="password-toggle"
              onClick={() => setShowPassword(!showPassword)}
            >
              {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
            </button>
          </div>
        </div>

        <button type="submit" className="btn btn-primary btn-block">
          {activeTab === 'register' ? (
            <>
              <UserPlus size={18} />
              Tạo tài khoản
            </>
          ) : (
            <>
              <LogIn size={18} />
              Đăng nhập
            </>
          )}
        </button>
      </form>
    </div>
  );
}
