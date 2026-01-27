import React, { useState } from 'react';
import {
  X,
  User,
  Mail,
  Phone,
  Building,
  UserCheck,
  Lock,
  Eye,
  EyeOff,
  AlertTriangle
} from 'lucide-react';
import '../../static/styles/admin.css';

/**
 * UserFormModal Component
 * 
 * Modal form for creating/editing users
 * - Validates all fields
 * - Shows clear error messages
 * - Excludes admin role for new users (admin only created internally)
 */
export default function UserFormModal({ mode, user, meta, onSubmit, onClose }) {
  const isEdit = mode === 'edit';
  
  const [formData, setFormData] = useState({
    username: user?.username || '',
    password: '',
    confirmPassword: '',
    email: user?.email || user?.profile?.email || '',
    is_active: user?.is_active ?? true,
    is_staff: user?.is_staff ?? false,
    full_name: user?.profile?.full_name || '',
    phone: user?.profile?.phone || '',
    role: user?.profile?.role || 'student',
    department: user?.profile?.department || '',
    notes: user?.profile?.notes || ''
  });
  
  const [errors, setErrors] = useState({});
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [submitError, setSubmitError] = useState('');

  const validate = () => {
    const newErrors = {};
    
    // Username validation
    if (!isEdit) {
      if (!formData.username.trim()) {
        newErrors.username = 'Tên đăng nhập không được để trống';
      } else if (formData.username.length < 3) {
        newErrors.username = 'Tên đăng nhập phải có ít nhất 3 ký tự';
      } else if (!/^[a-zA-Z0-9_]+$/.test(formData.username)) {
        newErrors.username = 'Tên đăng nhập chỉ được chứa chữ cái, số và dấu gạch dưới';
      }
    }
    
    // Password validation (required for new users)
    if (!isEdit) {
      if (!formData.password) {
        newErrors.password = 'Mật khẩu không được để trống';
      } else if (formData.password.length < 8) {
        newErrors.password = 'Mật khẩu phải có ít nhất 8 ký tự';
      }
      
      if (formData.password !== formData.confirmPassword) {
        newErrors.confirmPassword = 'Mật khẩu xác nhận không khớp';
      }
    } else if (formData.password) {
      // Password is optional for edit, but if provided, must be valid
      if (formData.password.length < 8) {
        newErrors.password = 'Mật khẩu phải có ít nhất 8 ký tự';
      }
      if (formData.password !== formData.confirmPassword) {
        newErrors.confirmPassword = 'Mật khẩu xác nhận không khớp';
      }
    }
    
    // Full name validation
    if (!formData.full_name.trim()) {
      newErrors.full_name = 'Họ tên không được để trống';
    } else if (formData.full_name.length > 128) {
      newErrors.full_name = 'Họ tên quá dài (tối đa 128 ký tự)';
    }
    
    // Email validation
    if (!formData.email.trim()) {
      newErrors.email = 'Email không được để trống';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      newErrors.email = 'Email không hợp lệ';
    }
    
    // Phone validation (optional but format check if provided)
    if (formData.phone && !/^[0-9+\-\s()]{8,20}$/.test(formData.phone)) {
      newErrors.phone = 'Số điện thoại không hợp lệ';
    }
    
    // Role validation
    if (!formData.role) {
      newErrors.role = 'Vui lòng chọn vai trò';
    }
    
    // Department validation
    if (!formData.department) {
      newErrors.department = 'Vui lòng chọn khoa/phòng ban';
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
    // Clear error for this field
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: '' }));
    }
    setSubmitError('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validate()) return;
    
    setLoading(true);
    setSubmitError('');
    
    try {
      // Prepare data for API
      const apiData = {
        username: formData.username,
        email: formData.email,
        is_active: formData.is_active,
        is_staff: formData.is_staff,
        profile: {
          full_name: formData.full_name,
          phone: formData.phone,
          role: formData.role,
          department: formData.department,
          notes: formData.notes
        }
      };
      
      // Only include password if provided
      if (formData.password) {
        apiData.password = formData.password;
      }
      
      await onSubmit(apiData);
    } catch (err) {
      const errorMsg = err.message || 'Đã xảy ra lỗi';
      // Try to parse JSON error
      try {
        const errData = JSON.parse(errorMsg);
        setSubmitError(errData.error || errorMsg);
      } catch {
        setSubmitError(errorMsg);
      }
    } finally {
      setLoading(false);
    }
  };

  // Filter out admin role for new users
  const availableRoles = isEdit 
    ? meta.roles 
    : meta.roles?.filter(r => r.value !== 'admin');

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content user-form-modal" onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="modal-header">
          <h2>
            <User size={20} />
            {isEdit ? 'Chỉnh sửa người dùng' : 'Thêm người dùng mới'}
          </h2>
          <button className="btn-close" onClick={onClose}>
            <X size={20} />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="user-form">
          {submitError && (
            <div className="form-error-banner">
              <AlertTriangle size={18} />
              {submitError}
            </div>
          )}

          <div className="form-section">
            <h3>Thông tin đăng nhập</h3>
            
            <div className="form-row">
              <div className={`form-group ${errors.username ? 'has-error' : ''}`}>
                <label>
                  <User size={16} />
                  Tên đăng nhập <span className="required">*</span>
                </label>
                <input
                  type="text"
                  name="username"
                  value={formData.username}
                  onChange={handleChange}
                  disabled={isEdit}
                  placeholder="Nhập tên đăng nhập"
                />
                {errors.username && <span className="error-text">{errors.username}</span>}
              </div>
              
              <div className={`form-group ${errors.email ? 'has-error' : ''}`}>
                <label>
                  <Mail size={16} />
                  Email <span className="required">*</span>
                </label>
                <input
                  type="email"
                  name="email"
                  value={formData.email}
                  onChange={handleChange}
                  placeholder="Nhập email"
                />
                {errors.email && <span className="error-text">{errors.email}</span>}
              </div>
            </div>

            <div className="form-row">
              <div className={`form-group ${errors.password ? 'has-error' : ''}`}>
                <label>
                  <Lock size={16} />
                  Mật khẩu {!isEdit && <span className="required">*</span>}
                </label>
                <div className="password-input">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    name="password"
                    value={formData.password}
                    onChange={handleChange}
                    placeholder={isEdit ? 'Để trống nếu không thay đổi' : 'Nhập mật khẩu'}
                  />
                  <button 
                    type="button" 
                    className="toggle-password"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                  </button>
                </div>
                {errors.password && <span className="error-text">{errors.password}</span>}
              </div>
              
              <div className={`form-group ${errors.confirmPassword ? 'has-error' : ''}`}>
                <label>
                  <Lock size={16} />
                  Xác nhận mật khẩu {!isEdit && <span className="required">*</span>}
                </label>
                <input
                  type={showPassword ? 'text' : 'password'}
                  name="confirmPassword"
                  value={formData.confirmPassword}
                  onChange={handleChange}
                  placeholder="Nhập lại mật khẩu"
                />
                {errors.confirmPassword && <span className="error-text">{errors.confirmPassword}</span>}
              </div>
            </div>
          </div>

          <div className="form-section">
            <h3>Thông tin cá nhân</h3>
            
            <div className="form-row">
              <div className={`form-group ${errors.full_name ? 'has-error' : ''}`}>
                <label>
                  <UserCheck size={16} />
                  Họ và tên <span className="required">*</span>
                </label>
                <input
                  type="text"
                  name="full_name"
                  value={formData.full_name}
                  onChange={handleChange}
                  placeholder="Nhập họ và tên"
                />
                {errors.full_name && <span className="error-text">{errors.full_name}</span>}
              </div>
              
              <div className={`form-group ${errors.phone ? 'has-error' : ''}`}>
                <label>
                  <Phone size={16} />
                  Số điện thoại
                </label>
                <input
                  type="tel"
                  name="phone"
                  value={formData.phone}
                  onChange={handleChange}
                  placeholder="Nhập số điện thoại"
                />
                {errors.phone && <span className="error-text">{errors.phone}</span>}
              </div>
            </div>

            <div className="form-row">
              <div className={`form-group ${errors.role ? 'has-error' : ''}`}>
                <label>
                  <UserCheck size={16} />
                  Vai trò <span className="required">*</span>
                </label>
                <select name="role" value={formData.role} onChange={handleChange}>
                  <option value="">-- Chọn vai trò --</option>
                  {availableRoles?.map(r => (
                    <option key={r.value} value={r.value}>{r.label}</option>
                  ))}
                </select>
                {errors.role && <span className="error-text">{errors.role}</span>}
              </div>
              
              <div className={`form-group ${errors.department ? 'has-error' : ''}`}>
                <label>
                  <Building size={16} />
                  Khoa/Phòng ban <span className="required">*</span>
                </label>
                <select name="department" value={formData.department} onChange={handleChange}>
                  <option value="">-- Chọn khoa/phòng ban --</option>
                  {meta.departments?.map(d => (
                    <option key={d.value} value={d.value}>{d.label}</option>
                  ))}
                </select>
                {errors.department && <span className="error-text">{errors.department}</span>}
              </div>
            </div>

            <div className="form-group">
              <label>Ghi chú</label>
              <textarea
                name="notes"
                value={formData.notes}
                onChange={handleChange}
                placeholder="Ghi chú thêm (tùy chọn)"
                rows={3}
              />
            </div>
          </div>

          <div className="form-section">
            <h3>Trạng thái tài khoản</h3>
            
            <div className="form-row checkboxes">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  name="is_active"
                  checked={formData.is_active}
                  onChange={handleChange}
                />
                <span className="checkmark" />
                Tài khoản hoạt động
              </label>
              
              {isEdit && (
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    name="is_staff"
                    checked={formData.is_staff}
                    onChange={handleChange}
                  />
                  <span className="checkmark" />
                  Quyền quản trị (Admin)
                </label>
              )}
            </div>
          </div>

          {/* Footer */}
          <div className="modal-footer">
            <button type="button" className="btn-cancel" onClick={onClose}>
              Hủy
            </button>
            <button type="submit" className="btn-primary" disabled={loading}>
              {loading ? 'Đang xử lý...' : isEdit ? 'Cập nhật' : 'Tạo mới'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
