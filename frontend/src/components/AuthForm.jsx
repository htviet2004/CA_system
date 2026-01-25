import React, { useState, useEffect } from 'react';
import { UserPlus, LogIn, Eye, EyeOff, X, User, Mail, Phone, Building, Briefcase, Lock } from 'lucide-react';
import '../static/styles/auth.css';

const API_BASE = '/api/usermanage';

export default function AuthForm({ onRegister, onLogin, onClose }) {
  const [activeTab, setActiveTab] = useState('login');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  
  // Form data for registration
  const [formData, setFormData] = useState({
    username: '',
    password: '',
    confirmPassword: '',
    fullName: '',
    email: '',
    phone: '',
    department: '',
    role: 'student'  // Default role
  });
  
  // Meta data for dropdowns
  const [roles, setRoles] = useState([]);
  const [departments, setDepartments] = useState([]);

  // Fetch roles and departments on mount
  useEffect(() => {
    const fetchMeta = async () => {
      try {
        const [rolesRes, deptsRes] = await Promise.all([
          fetch(`${API_BASE}/meta/roles/`),
          fetch(`${API_BASE}/meta/departments/`)
        ]);
        
        if (rolesRes.ok) {
          const rolesData = await rolesRes.json();
          // Filter out 'admin' role for registration
          const filteredRoles = rolesData.roles.filter(r => r.value !== 'admin');
          setRoles(filteredRoles);
        }
        
        if (deptsRes.ok) {
          const deptsData = await deptsRes.json();
          setDepartments(deptsData.departments);
        }
      } catch (err) {
        console.error('Failed to fetch meta data:', err);
      }
    };
    
    fetchMeta();
  }, []);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    setError(''); // Clear error on input change
  };

  const validateRegistrationForm = () => {
    if (!formData.username.trim()) {
      setError('Vui lòng nhập tên đăng nhập');
      return false;
    }
    
    if (formData.username.length < 3) {
      setError('Tên đăng nhập phải có ít nhất 3 ký tự');
      return false;
    }
    
    if (!/^[a-zA-Z0-9_]+$/.test(formData.username)) {
      setError('Tên đăng nhập chỉ được chứa chữ cái, số và dấu gạch dưới');
      return false;
    }
    
    if (!formData.password) {
      setError('Vui lòng nhập mật khẩu');
      return false;
    }
    
    if (formData.password.length < 8) {
      setError('Mật khẩu phải có ít nhất 8 ký tự');
      return false;
    }
    
    if (formData.password !== formData.confirmPassword) {
      setError('Mật khẩu xác nhận không khớp');
      return false;
    }
    
    if (!formData.fullName.trim()) {
      setError('Vui lòng nhập họ tên đầy đủ');
      return false;
    }
    
    if (!formData.email.trim()) {
      setError('Vui lòng nhập email');
      return false;
    }
    
    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(formData.email)) {
      setError('Email không hợp lệ');
      return false;
    }
    
    if (!formData.department) {
      setError('Vui lòng chọn khoa/phòng ban');
      return false;
    }
    
    if (!formData.role) {
      setError('Vui lòng chọn vai trò');
      return false;
    }
    
    return true;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    
    if (activeTab === 'register') {
      // Validate registration form
      if (!validateRegistrationForm()) {
        return;
      }
      
      // Create enhanced event with all form data
      const enhancedEvent = {
        preventDefault: () => {},
        target: {
          username: { value: formData.username },
          password: { value: formData.password },
          full_name: { value: formData.fullName },
          email: { value: formData.email },
          phone: { value: formData.phone },
          department: { value: formData.department },
          role: { value: formData.role }
        }
      };
      
      setLoading(true);
      try {
        await onRegister(enhancedEvent);
      } catch (err) {
        setError(err.message || 'Đăng ký thất bại');
      } finally {
        setLoading(false);
      }
    } else {
      // Login - simple validation
      if (!formData.username || !formData.password) {
        setError('Vui lòng nhập tên đăng nhập và mật khẩu');
        return;
      }
      
      const loginEvent = {
        preventDefault: () => {},
        target: {
          username: { value: formData.username },
          password: { value: formData.password }
        }
      };
      
      setLoading(true);
      try {
        await onLogin(loginEvent);
      } catch (err) {
        setError(err.message || 'Đăng nhập thất bại');
      } finally {
        setLoading(false);
      }
    }
  };

  const switchTab = (tab) => {
    setActiveTab(tab);
    setError('');
    // Reset form data when switching tabs
    setFormData({
      username: '',
      password: '',
      confirmPassword: '',
      fullName: '',
      email: '',
      phone: '',
      department: '',
      role: 'student'
    });
  };

  // Login form - simple table
  const renderLoginForm = () => (
    <div className="auth-form-content">
      <table className="auth-table">
        <tbody>
          <tr>
            <td className="label-cell">
              <label htmlFor="username">
                <User size={16} />
                Tên đăng nhập
              </label>
            </td>
            <td className="input-cell">
              <input
                type="text"
                id="username"
                name="username"
                value={formData.username}
                onChange={handleInputChange}
                placeholder="Nhập tên đăng nhập"
                required
                autoComplete="username"
              />
            </td>
          </tr>
          <tr>
            <td className="label-cell">
              <label htmlFor="password">
                <Lock size={16} />
                Mật khẩu
              </label>
            </td>
            <td className="input-cell">
              <div className="password-input">
                <input
                  type={showPassword ? 'text' : 'password'}
                  id="password"
                  name="password"
                  value={formData.password}
                  onChange={handleInputChange}
                  placeholder="Nhập mật khẩu"
                  required
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  );

  // Registration form - table layout with scroll
  const renderRegisterForm = () => (
    <div className="auth-form-content auth-form-scroll">
      <table className="auth-table">
        <tbody>
          {/* Section: Thông tin tài khoản */}
          <tr className="section-header">
            <td colSpan="2">
              <div className="section-title">🔐 Thông tin tài khoản</div>
            </td>
          </tr>
          
          <tr>
            <td className="label-cell">
              <label htmlFor="username">
                <User size={16} />
                Tên đăng nhập <span className="required">*</span>
              </label>
            </td>
            <td className="input-cell">
              <input
                type="text"
                id="username"
                name="username"
                value={formData.username}
                onChange={handleInputChange}
                placeholder="Nhập tên đăng nhập"
                required
                autoComplete="username"
              />
              <small className="field-hint">Chỉ dùng chữ cái, số và dấu gạch dưới</small>
            </td>
          </tr>
          
          <tr>
            <td className="label-cell">
              <label htmlFor="password">
                <Lock size={16} />
                Mật khẩu <span className="required">*</span>
              </label>
            </td>
            <td className="input-cell">
              <div className="password-input">
                <input
                  type={showPassword ? 'text' : 'password'}
                  id="password"
                  name="password"
                  value={formData.password}
                  onChange={handleInputChange}
                  placeholder="Nhập mật khẩu"
                  required
                  autoComplete="new-password"
                />
                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
              <small className="field-hint">Tối thiểu 8 ký tự</small>
            </td>
          </tr>
          
          <tr>
            <td className="label-cell">
              <label htmlFor="confirmPassword">
                <Lock size={16} />
                Xác nhận mật khẩu <span className="required">*</span>
              </label>
            </td>
            <td className="input-cell">
              <div className="password-input">
                <input
                  type={showPassword ? 'text' : 'password'}
                  id="confirmPassword"
                  name="confirmPassword"
                  value={formData.confirmPassword}
                  onChange={handleInputChange}
                  placeholder="Nhập lại mật khẩu"
                  required
                  autoComplete="new-password"
                />
              </div>
            </td>
          </tr>

          {/* Section: Thông tin cá nhân */}
          <tr className="section-header">
            <td colSpan="2">
              <div className="section-title">👤 Thông tin cá nhân</div>
            </td>
          </tr>
          
          <tr>
            <td className="label-cell">
              <label htmlFor="fullName">
                <User size={16} />
                Họ và tên <span className="required">*</span>
              </label>
            </td>
            <td className="input-cell">
              <input
                type="text"
                id="fullName"
                name="fullName"
                value={formData.fullName}
                onChange={handleInputChange}
                placeholder="Nguyễn Văn A"
                required
              />
              <small className="field-hint">Tên này sẽ hiển thị trên chứng thư số</small>
            </td>
          </tr>
          
          <tr>
            <td className="label-cell">
              <label htmlFor="email">
                <Mail size={16} />
                Email <span className="required">*</span>
              </label>
            </td>
            <td className="input-cell">
              <input
                type="email"
                id="email"
                name="email"
                value={formData.email}
                onChange={handleInputChange}
                placeholder="email@example.com"
                required
              />
            </td>
          </tr>
          
          <tr>
            <td className="label-cell">
              <label htmlFor="phone">
                <Phone size={16} />
                Số điện thoại
              </label>
            </td>
            <td className="input-cell">
              <input
                type="tel"
                id="phone"
                name="phone"
                value={formData.phone}
                onChange={handleInputChange}
                placeholder="+84 xxx xxx xxx"
              />
            </td>
          </tr>

          {/* Section: Thông tin tổ chức */}
          <tr className="section-header">
            <td colSpan="2">
              <div className="section-title">🏢 Thông tin tổ chức</div>
            </td>
          </tr>
          
          <tr>
            <td className="label-cell">
              <label htmlFor="department">
                <Building size={16} />
                Khoa / Phòng ban <span className="required">*</span>
              </label>
            </td>
            <td className="input-cell">
              <select
                id="department"
                name="department"
                value={formData.department}
                onChange={handleInputChange}
                required
              >
                <option value="">-- Chọn khoa/phòng ban --</option>
                {departments.map(dept => (
                  <option key={dept.value} value={dept.value}>
                    {dept.label}
                  </option>
                ))}
              </select>
            </td>
          </tr>
          
          <tr>
            <td className="label-cell">
              <label htmlFor="role">
                <Briefcase size={16} />
                Vai trò <span className="required">*</span>
              </label>
            </td>
            <td className="input-cell">
              <select
                id="role"
                name="role"
                value={formData.role}
                onChange={handleInputChange}
                required
              >
                <option value="">-- Chọn vai trò --</option>
                {roles.map(role => (
                  <option key={role.value} value={role.value}>
                    {role.label}
                  </option>
                ))}
              </select>
              <small className="field-hint">Vai trò quyết định quyền hạn trong hệ thống</small>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  );

  return (
    <div className={`auth-modal-card ${activeTab === 'register' ? 'register-mode' : ''}`}>
      <button className="modal-close" onClick={onClose}>
        <X size={24} />
      </button>

      <div className="auth-modal-header">
        <h2>{activeTab === 'login' ? 'Đăng nhập' : 'Đăng ký tài khoản'}</h2>
        <p>
          {activeTab === 'login' 
            ? 'Vui lòng đăng nhập để sử dụng dịch vụ ký số' 
            : 'Tạo tài khoản mới để bắt đầu sử dụng dịch vụ ký số PKI'}
        </p>
      </div>

      <div className="auth-tabs">
        <button
          className={`auth-tab ${activeTab === 'login' ? 'active' : ''}`}
          onClick={() => switchTab('login')}
        >
          <LogIn size={18} />
          Đăng nhập
        </button>
        <button
          className={`auth-tab ${activeTab === 'register' ? 'active' : ''}`}
          onClick={() => switchTab('register')}
        >
          <UserPlus size={18} />
          Đăng ký
        </button>
      </div>

      {error && (
        <div className="auth-error">
          <span>{error}</span>
        </div>
      )}

      <form className="auth-form" onSubmit={handleSubmit}>
        {activeTab === 'login' ? renderLoginForm() : renderRegisterForm()}

        <button 
          type="submit" 
          className="btn btn-primary btn-block"
          disabled={loading}
        >
          {loading ? (
            <span>Đang xử lý...</span>
          ) : activeTab === 'register' ? (
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

      {activeTab === 'register' && (
        <div className="auth-footer">
          <p className="pki-notice">
            🔐 Sau khi đăng ký, hệ thống sẽ tự động cấp chứng thư số PKI cho bạn.
            Chứng thư này được sử dụng để ký số các tài liệu PDF.
          </p>
        </div>
      )}
    </div>
  );
}
