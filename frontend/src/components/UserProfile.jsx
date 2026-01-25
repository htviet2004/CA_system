import React, { useEffect, useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  User, 
  Mail, 
  Phone, 
  Building2, 
  Shield, 
  FileText,
  ArrowLeft,
  Save,
  AlertCircle,
  CheckCircle,
  Info
} from 'lucide-react';
import '../static/styles/userinfo.css';
import { updateProfile, fetchProfile, fetchRoles, fetchDepartments } from '../api';

/**
 * UserProfile Component
 * 
 * Features:
 * - Editable profile fields with validation
 * - Role and department dropdowns from API
 * - Role-based permissions (only admin can edit roles)
 * - Inline validation errors
 * - Save disabled until changes detected
 * - PKI notes about which fields affect certificates
 */
export default function UserProfile({ username, onBack, showMessage, isAdmin = false }) {
  const navigate = useNavigate();
  
  // Form state
  const [form, setForm] = useState({
    full_name: '',
    phone: '',
    department: '',
    role: '',
    email: '',
    notes: ''
  });
  
  // Original form state for change detection
  const [originalForm, setOriginalForm] = useState(null);
  
  // UI state
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [errors, setErrors] = useState({});
  const [canEdit, setCanEdit] = useState(false);
  const [canEditRole, setCanEditRole] = useState(false);
  
  // Meta data for dropdowns
  const [roles, setRoles] = useState([]);
  const [departments, setDepartments] = useState([]);
  
  // Success message
  const [successMessage, setSuccessMessage] = useState('');

  // Check if form has changes
  const hasChanges = useMemo(() => {
    if (!originalForm) return false;
    return Object.keys(form).some(key => form[key] !== originalForm[key]);
  }, [form, originalForm]);

  // Load meta data (roles and departments)
  useEffect(() => {
    const loadMeta = async () => {
      try {
        const [rolesRes, deptsRes] = await Promise.all([
          fetchRoles(),
          fetchDepartments()
        ]);
        setRoles(rolesRes.roles || []);
        setDepartments(deptsRes.departments || []);
      } catch (err) {
        console.error('Failed to load meta data:', err);
        // Set fallback values
        setRoles([
          { value: 'student', label: 'Student' },
          { value: 'lecturer', label: 'Lecturer' },
          { value: 'staff', label: 'Staff' },
          { value: 'admin', label: 'Administrator' }
        ]);
        setDepartments([
          { value: 'cntt', label: 'Khoa Công nghệ Thông tin' },
          { value: 'dtvt', label: 'Khoa Điện tử Viễn thông' },
          { value: 'other', label: 'Khác' }
        ]);
      }
    };
    loadMeta();
  }, []);

  // Load profile data
  useEffect(() => {
    let mounted = true;
    
    const loadProfile = async () => {
      if (!username) {
        setLoading(false);
        return;
      }
      
      try {
        const res = await fetchProfile(username);
        if (!mounted) return;
        
        if (res && res.profile) {
          const profileData = {
            full_name: res.profile.full_name || '',
            phone: res.profile.phone || '',
            department: res.profile.department || '',
            role: res.profile.role || '',
            email: res.profile.email || '',
            notes: res.profile.notes || ''
          };
          setForm(profileData);
          setOriginalForm(profileData);
          setCanEdit(res.can_edit !== false);
          setCanEditRole(res.can_edit_role === true || isAdmin);
        }
      } catch (err) {
        console.error('Failed to load profile:', err);
        if (showMessage) {
          showMessage('Không thể tải thông tin hồ sơ', 'error');
        }
      } finally {
        if (mounted) setLoading(false);
      }
    };
    
    loadProfile();
    return () => { mounted = false; };
  }, [username, isAdmin, showMessage]);

  // Handle input changes
  const handleChange = (e) => {
    const { name, value } = e.target;
    setForm(prev => ({ ...prev, [name]: value }));
    
    // Clear error for this field
    if (errors[name]) {
      setErrors(prev => {
        const newErrors = { ...prev };
        delete newErrors[name];
        return newErrors;
      });
    }
    
    // Clear success message on any change
    setSuccessMessage('');
  };

  // Validate form
  const validateForm = () => {
    const newErrors = {};
    
    // Phone validation
    if (form.phone) {
      const phoneClean = form.phone.replace(/[\s\-\(\)]/g, '');
      if (!/^\+?[0-9]{8,15}$/.test(phoneClean)) {
        newErrors.phone = 'Số điện thoại không hợp lệ. Ví dụ: +84 123 456 789';
      }
    }
    
    // Email validation
    if (form.email) {
      if (!/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(form.email)) {
        newErrors.email = 'Email không hợp lệ';
      }
    }
    
    // Full name length
    if (form.full_name && form.full_name.length > 100) {
      newErrors.full_name = 'Họ tên tối đa 100 ký tự';
    }
    
    // Notes length
    if (form.notes && form.notes.length > 500) {
      newErrors.notes = 'Ghi chú tối đa 500 ký tự';
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  // Handle form submission
  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) return;
    if (!hasChanges) return;
    
    setSaving(true);
    setSuccessMessage('');
    
    try {
      const payload = { username, ...form };
      const res = await updateProfile(payload);
      
      if (res.errors) {
        setErrors(res.errors);
      } else if (res.ok) {
        setOriginalForm({ ...form });
        setSuccessMessage('Lưu thông tin thành công');
        if (showMessage) {
          showMessage('Lưu thông tin thành công', 'success');
        }
      }
    } catch (err) {
      console.error('Profile update error:', err);
      const errorMsg = err.message || 'Lỗi khi lưu thông tin';
      if (showMessage) {
        showMessage(errorMsg, 'error');
      }
      setErrors({ _general: errorMsg });
    } finally {
      setSaving(false);
    }
  };

  // Handle back navigation
  const handleBack = () => {
    if (onBack) {
      onBack();
    } else {
      navigate('/sign');
    }
  };

  if (loading) {
    return (
      <div className="userinfo-container">
        <div className="userinfo-loading">
          <div className="loading-spinner"></div>
          <p>Đang tải...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="userinfo-container">
      <div className="userinfo-header">
        <button type="button" className="btn-back" onClick={handleBack}>
          <ArrowLeft size={18} />
          Quay lại
        </button>
        <h2>Thông tin cá nhân</h2>
      </div>

      {/* PKI Notice */}
      <div className="userinfo-notice">
        <Info size={16} />
        <span>
          <strong>Lưu ý PKI:</strong> Thay đổi <em>Họ tên</em> hoặc <em>Email</em> có thể 
          ảnh hưởng đến chứng chỉ số được cấp trong tương lai, 
          nhưng <strong>không</strong> làm vô hiệu chứng chỉ hiện tại.
        </span>
      </div>

      {/* Success Message */}
      {successMessage && (
        <div className="userinfo-message success">
          <CheckCircle size={16} />
          {successMessage}
        </div>
      )}

      {/* General Error */}
      {errors._general && (
        <div className="userinfo-message error">
          <AlertCircle size={16} />
          {errors._general}
        </div>
      )}

      <form onSubmit={handleSubmit} className="userinfo-form">
        {/* Full Name - affects certificate CN */}
        <div className={`form-group ${errors.full_name ? 'has-error' : ''}`}>
          <label htmlFor="full_name">
            <User size={16} />
            Họ và tên
            <span className="field-hint">(Có thể được sử dụng trong chứng chỉ số)</span>
          </label>
          <input
            id="full_name"
            name="full_name"
            type="text"
            value={form.full_name}
            onChange={handleChange}
            placeholder="Nguyễn Văn A"
            disabled={!canEdit}
            maxLength={100}
          />
          {errors.full_name && (
            <span className="field-error">
              <AlertCircle size={14} />
              {errors.full_name}
            </span>
          )}
        </div>

        {/* Email - affects certificate SAN */}
        <div className={`form-group ${errors.email ? 'has-error' : ''}`}>
          <label htmlFor="email">
            <Mail size={16} />
            Email
            <span className="field-hint">(Có thể được sử dụng trong chứng chỉ số)</span>
          </label>
          <input
            id="email"
            name="email"
            type="email"
            value={form.email}
            onChange={handleChange}
            placeholder="example@university.edu.vn"
            disabled={!canEdit}
            maxLength={254}
          />
          {errors.email && (
            <span className="field-error">
              <AlertCircle size={14} />
              {errors.email}
            </span>
          )}
        </div>

        {/* Phone Number */}
        <div className={`form-group ${errors.phone ? 'has-error' : ''}`}>
          <label htmlFor="phone">
            <Phone size={16} />
            Số điện thoại
          </label>
          <input
            id="phone"
            name="phone"
            type="tel"
            value={form.phone}
            onChange={handleChange}
            placeholder="+84 123 456 789"
            disabled={!canEdit}
            maxLength={20}
          />
          {errors.phone && (
            <span className="field-error">
              <AlertCircle size={14} />
              {errors.phone}
            </span>
          )}
        </div>

        {/* Department - SELECT dropdown */}
        <div className={`form-group ${errors.department ? 'has-error' : ''}`}>
          <label htmlFor="department">
            <Building2 size={16} />
            Khoa / Phòng ban
          </label>
          <select
            id="department"
            name="department"
            value={form.department}
            onChange={handleChange}
            disabled={!canEdit}
          >
            <option value="">-- Chọn khoa / phòng ban --</option>
            {departments.map(dept => (
              <option key={dept.value} value={dept.value}>
                {dept.label}
              </option>
            ))}
          </select>
          {errors.department && (
            <span className="field-error">
              <AlertCircle size={14} />
              {errors.department}
            </span>
          )}
        </div>

        {/* Role - SELECT dropdown (admin only can edit) */}
        <div className={`form-group ${errors.role ? 'has-error' : ''}`}>
          <label htmlFor="role">
            <Shield size={16} />
            Vai trò
            {!canEditRole && (
              <span className="field-hint">(Chỉ quản trị viên có thể thay đổi)</span>
            )}
          </label>
          <div className="role-field-wrapper">
            <select
              id="role"
              name="role"
              value={form.role}
              onChange={handleChange}
              disabled={!canEditRole}
              className={!canEditRole ? 'readonly' : ''}
            >
              <option value="">-- Chọn vai trò --</option>
              {roles.map(role => (
                <option key={role.value} value={role.value}>
                  {role.label}
                </option>
              ))}
            </select>
            {form.role && (
              <span className={`role-badge role-${form.role}`}>
                {roles.find(r => r.value === form.role)?.label || form.role}
              </span>
            )}
          </div>
          {errors.role && (
            <span className="field-error">
              <AlertCircle size={14} />
              {errors.role}
            </span>
          )}
        </div>

        {/* Notes */}
        <div className={`form-group ${errors.notes ? 'has-error' : ''}`}>
          <label htmlFor="notes">
            <FileText size={16} />
            Ghi chú
            <span className="field-hint">({form.notes.length}/500)</span>
          </label>
          <textarea
            id="notes"
            name="notes"
            value={form.notes}
            onChange={handleChange}
            placeholder="Thông tin bổ sung (tùy chọn)"
            disabled={!canEdit}
            maxLength={500}
            rows={3}
          />
          {errors.notes && (
            <span className="field-error">
              <AlertCircle size={14} />
              {errors.notes}
            </span>
          )}
        </div>

        {/* Actions */}
        <div className="userinfo-actions">
          <button 
            type="submit" 
            className="btn btn-primary"
            disabled={!canEdit || !hasChanges || saving}
          >
            {saving ? (
              <>
                <span className="btn-spinner"></span>
                Đang lưu...
              </>
            ) : (
              <>
                <Save size={18} />
                Lưu thay đổi
              </>
            )}
          </button>
          
          {!hasChanges && canEdit && (
            <span className="no-changes-hint">
              Chưa có thay đổi nào
            </span>
          )}
        </div>
      </form>
    </div>
  );
}
