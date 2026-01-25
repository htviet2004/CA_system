import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  Key,
  Eye,
  EyeOff,
  Lock,
  CheckCircle,
  AlertTriangle
} from 'lucide-react';
import { changePassword } from '../api';
import '../static/styles/auth.css';

/**
 * ChangePassword Component
 * 
 * Allows users to change their password with:
 * - Current password verification
 * - New password with confirmation
 * - Password strength validation
 */
export default function ChangePassword({ showMessage, onBack }) {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });
  const [showPasswords, setShowPasswords] = useState({
    current: false,
    new: false,
    confirm: false
  });
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState({});

  const validatePassword = (password) => {
    const checks = {
      length: password.length >= 8,
      uppercase: /[A-Z]/.test(password),
      lowercase: /[a-z]/.test(password),
      number: /[0-9]/.test(password)
    };
    return checks;
  };

  const passwordStrength = validatePassword(formData.newPassword);
  const allChecksPass = Object.values(passwordStrength).every(Boolean);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    setErrors(prev => ({ ...prev, [name]: '' }));
  };

  const togglePassword = (field) => {
    setShowPasswords(prev => ({ ...prev, [field]: !prev[field] }));
  };

  const validate = () => {
    const newErrors = {};

    if (!formData.currentPassword) {
      newErrors.currentPassword = 'Vui lòng nhập mật khẩu hiện tại';
    }

    if (!formData.newPassword) {
      newErrors.newPassword = 'Vui lòng nhập mật khẩu mới';
    } else if (!allChecksPass) {
      newErrors.newPassword = 'Mật khẩu không đủ mạnh';
    }

    if (!formData.confirmPassword) {
      newErrors.confirmPassword = 'Vui lòng xác nhận mật khẩu mới';
    } else if (formData.newPassword !== formData.confirmPassword) {
      newErrors.confirmPassword = 'Mật khẩu xác nhận không khớp';
    }

    if (formData.currentPassword === formData.newPassword) {
      newErrors.newPassword = 'Mật khẩu mới phải khác mật khẩu hiện tại';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validate()) return;

    try {
      setLoading(true);
      await changePassword(formData.currentPassword, formData.newPassword);
      showMessage?.('Đổi mật khẩu thành công!', 'success');
      navigate(-1);
    } catch (err) {
      const errorMsg = err.message || 'Đổi mật khẩu thất bại';
      if (errorMsg.includes('incorrect') || errorMsg.includes('sai')) {
        setErrors({ currentPassword: 'Mật khẩu hiện tại không đúng' });
      } else {
        showMessage?.(errorMsg, 'error');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="change-password-container">
      <div className="change-password-card">
        {/* Header */}
        <div className="card-header">
          <button className="back-button" onClick={onBack || (() => navigate(-1))}>
            <ArrowLeft size={20} />
            Quay lại
          </button>
          <h1 className="card-title">
            <Key size={24} />
            Đổi mật khẩu
          </h1>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="password-form">
          {/* Current Password */}
          <div className="form-group">
            <label htmlFor="currentPassword">
              <Lock size={16} />
              Mật khẩu hiện tại
            </label>
            <div className="password-input-wrapper">
              <input
                type={showPasswords.current ? 'text' : 'password'}
                id="currentPassword"
                name="currentPassword"
                value={formData.currentPassword}
                onChange={handleChange}
                placeholder="Nhập mật khẩu hiện tại"
                className={errors.currentPassword ? 'error' : ''}
              />
              <button
                type="button"
                className="toggle-password"
                onClick={() => togglePassword('current')}
              >
                {showPasswords.current ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
            {errors.currentPassword && (
              <span className="error-message">{errors.currentPassword}</span>
            )}
          </div>

          {/* New Password */}
          <div className="form-group">
            <label htmlFor="newPassword">
              <Key size={16} />
              Mật khẩu mới
            </label>
            <div className="password-input-wrapper">
              <input
                type={showPasswords.new ? 'text' : 'password'}
                id="newPassword"
                name="newPassword"
                value={formData.newPassword}
                onChange={handleChange}
                placeholder="Nhập mật khẩu mới"
                className={errors.newPassword ? 'error' : ''}
              />
              <button
                type="button"
                className="toggle-password"
                onClick={() => togglePassword('new')}
              >
                {showPasswords.new ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
            {errors.newPassword && (
              <span className="error-message">{errors.newPassword}</span>
            )}

            {/* Password Strength Indicators */}
            {formData.newPassword && (
              <div className="password-strength">
                <div className={`strength-item ${passwordStrength.length ? 'valid' : ''}`}>
                  {passwordStrength.length ? <CheckCircle size={14} /> : <AlertTriangle size={14} />}
                  Ít nhất 8 ký tự
                </div>
                <div className={`strength-item ${passwordStrength.uppercase ? 'valid' : ''}`}>
                  {passwordStrength.uppercase ? <CheckCircle size={14} /> : <AlertTriangle size={14} />}
                  Có chữ hoa (A-Z)
                </div>
                <div className={`strength-item ${passwordStrength.lowercase ? 'valid' : ''}`}>
                  {passwordStrength.lowercase ? <CheckCircle size={14} /> : <AlertTriangle size={14} />}
                  Có chữ thường (a-z)
                </div>
                <div className={`strength-item ${passwordStrength.number ? 'valid' : ''}`}>
                  {passwordStrength.number ? <CheckCircle size={14} /> : <AlertTriangle size={14} />}
                  Có số (0-9)
                </div>
              </div>
            )}
          </div>

          {/* Confirm Password */}
          <div className="form-group">
            <label htmlFor="confirmPassword">
              <Key size={16} />
              Xác nhận mật khẩu mới
            </label>
            <div className="password-input-wrapper">
              <input
                type={showPasswords.confirm ? 'text' : 'password'}
                id="confirmPassword"
                name="confirmPassword"
                value={formData.confirmPassword}
                onChange={handleChange}
                placeholder="Nhập lại mật khẩu mới"
                className={errors.confirmPassword ? 'error' : ''}
              />
              <button
                type="button"
                className="toggle-password"
                onClick={() => togglePassword('confirm')}
              >
                {showPasswords.confirm ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
            {errors.confirmPassword && (
              <span className="error-message">{errors.confirmPassword}</span>
            )}
            {formData.confirmPassword && formData.newPassword === formData.confirmPassword && (
              <span className="success-message">
                <CheckCircle size={14} />
                Mật khẩu khớp
              </span>
            )}
          </div>

          {/* Submit Button */}
          <button 
            type="submit" 
            className="submit-button"
            disabled={loading || !allChecksPass}
          >
            {loading ? 'Đang xử lý...' : 'Đổi mật khẩu'}
          </button>
        </form>
      </div>
    </div>
  );
}
