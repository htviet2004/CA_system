import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  Users,
  Shield,
  FileText,
  BarChart3,
  Search,
  Filter,
  Plus,
  Edit,
  Trash2,
  Eye,
  RefreshCw,
  Key,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Clock,
  Download,
  UserPlus,
  Settings,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';
import {
  getAdminStats,
  getAdminMeta,
  getAdminUsers,
  getAdminUser,
  createAdminUser,
  updateAdminUser,
  deleteAdminUser,
  getAdminCertificates,
  adminRevokeCertificate,
  getAdminSigningHistory,
  adminRevokeSignature
} from '../api';
import '../static/styles/admin.css';

/**
 * AdminDashboard Component
 * 
 * Full CRUD admin panel for managing:
 * - Users and profiles
 * - Certificates
 * - Signing history
 */
export default function AdminDashboard({ showMessage }) {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState(null);
  const [meta, setMeta] = useState({ roles: [], departments: [] });

  // Load initial data
  useEffect(() => {
    loadInitialData();
  }, []);

  const loadInitialData = async () => {
    try {
      setLoading(true);
      const [statsData, metaData] = await Promise.all([
        getAdminStats(),
        getAdminMeta()
      ]);
      setStats(statsData);
      setMeta(metaData);
    } catch (err) {
      showMessage?.('Lỗi tải dữ liệu: ' + err.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  const tabs = [
    { id: 'overview', label: 'Tổng quan', icon: BarChart3 },
    { id: 'users', label: 'Người dùng', icon: Users },
    { id: 'certificates', label: 'Chứng chỉ', icon: Shield },
    { id: 'history', label: 'Lịch sử ký số', icon: FileText },
  ];

  if (loading) {
    return (
      <div className="admin-container">
        <div className="loading-state">
          <RefreshCw size={32} className="spinning" />
          <p>Đang tải Admin Dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="admin-container">
      {/* Header */}
      <div className="admin-header">
        <button className="back-button" onClick={() => navigate(-1)}>
          <ArrowLeft size={20} />
          Quay lại
        </button>
        <h1 className="admin-title">
          <Settings size={28} />
          Admin Dashboard
        </h1>
      </div>

      {/* Tabs */}
      <div className="admin-tabs">
        {tabs.map(tab => (
          <button
            key={tab.id}
            className={`admin-tab ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            <tab.icon size={18} />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="admin-content">
        {activeTab === 'overview' && (
          <OverviewTab stats={stats} onRefresh={loadInitialData} />
        )}
        {activeTab === 'users' && (
          <UsersTab meta={meta} showMessage={showMessage} />
        )}
        {activeTab === 'certificates' && (
          <CertificatesTab meta={meta} showMessage={showMessage} />
        )}
        {activeTab === 'history' && (
          <SigningHistoryTab showMessage={showMessage} />
        )}
      </div>
    </div>
  );
}

// =============================================================================
// OVERVIEW TAB
// =============================================================================

function OverviewTab({ stats, onRefresh }) {
  if (!stats) return null;

  return (
    <div className="overview-tab">
      <div className="stats-header">
        <h2>Thống kê hệ thống</h2>
        <button className="refresh-btn" onClick={onRefresh}>
          <RefreshCw size={16} />
          Làm mới
        </button>
      </div>

      {/* Stats Cards */}
      <div className="stats-grid">
        <div className="stat-card users">
          <div className="stat-icon"><Users size={24} /></div>
          <div className="stat-info">
            <span className="stat-value">{stats.users.total}</span>
            <span className="stat-label">Tổng người dùng</span>
          </div>
          <div className="stat-details">
            <span className="detail-item success">{stats.users.active} hoạt động</span>
            <span className="detail-item info">{stats.users.admins} admin</span>
          </div>
        </div>

        <div className="stat-card certificates">
          <div className="stat-icon"><Shield size={24} /></div>
          <div className="stat-info">
            <span className="stat-value">{stats.certificates.total}</span>
            <span className="stat-label">Tổng chứng chỉ</span>
          </div>
          <div className="stat-details">
            <span className="detail-item success">{stats.certificates.active} hoạt động</span>
            <span className="detail-item warning">{stats.certificates.expiring_soon} sắp hết hạn</span>
          </div>
        </div>

        <div className="stat-card signatures">
          <div className="stat-icon"><FileText size={24} /></div>
          <div className="stat-info">
            <span className="stat-value">{stats.signatures.total}</span>
            <span className="stat-label">Tổng chữ ký</span>
          </div>
          <div className="stat-details">
            <span className="detail-item success">{stats.signatures.valid} hợp lệ</span>
            <span className="detail-item info">{stats.signatures.this_month} tháng này</span>
          </div>
        </div>

        <div className="stat-card new-users">
          <div className="stat-icon"><UserPlus size={24} /></div>
          <div className="stat-info">
            <span className="stat-value">{stats.users.new_this_month}</span>
            <span className="stat-label">Người dùng mới</span>
          </div>
          <div className="stat-details">
            <span className="detail-item">Trong tháng này</span>
          </div>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="recent-activity">
        <div className="activity-section">
          <h3>Người dùng mới đăng ký</h3>
          <div className="activity-list">
            {stats.recent_users.map((user, idx) => (
              <div key={idx} className="activity-item">
                <div className="activity-avatar">{user.username.charAt(0).toUpperCase()}</div>
                <div className="activity-info">
                  <span className="activity-name">{user.username}</span>
                  <span className="activity-time">{formatDate(user.date_joined)}</span>
                </div>
                <span className={`activity-status ${user.is_active ? 'active' : 'inactive'}`}>
                  {user.is_active ? 'Hoạt động' : 'Vô hiệu'}
                </span>
              </div>
            ))}
          </div>
        </div>

        <div className="activity-section">
          <h3>Chữ ký gần đây</h3>
          <div className="activity-list">
            {stats.recent_signatures.map((sig, idx) => (
              <div key={idx} className="activity-item">
                <div className="activity-icon"><FileText size={16} /></div>
                <div className="activity-info">
                  <span className="activity-name">{sig.document_name}</span>
                  <span className="activity-time">bởi {sig.username} • {formatDate(sig.signed_at)}</span>
                </div>
                <StatusBadge status={sig.status} />
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// =============================================================================
// USERS TAB
// =============================================================================

function UsersTab({ meta, showMessage }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [pagination, setPagination] = useState({ page: 1, total_pages: 1, total: 0 });
  const [filters, setFilters] = useState({
    search: '',
    is_active: '',
    is_staff: '',
    role: '',
    department: ''
  });
  const [showModal, setShowModal] = useState(null); // 'create', 'edit', 'view', 'delete'
  const [selectedUser, setSelectedUser] = useState(null);
  const [userDetail, setUserDetail] = useState(null);

  useEffect(() => {
    loadUsers();
  }, [pagination.page, filters.is_active, filters.is_staff, filters.role, filters.department]);

  // Debounced search
  useEffect(() => {
    const timer = setTimeout(() => {
      if (pagination.page === 1) {
        loadUsers();
      } else {
        setPagination(p => ({ ...p, page: 1 }));
      }
    }, 300);
    return () => clearTimeout(timer);
  }, [filters.search]);

  const loadUsers = async () => {
    try {
      setLoading(true);
      const data = await getAdminUsers({
        page: pagination.page,
        per_page: 15,
        search: filters.search || undefined,
        is_active: filters.is_active || undefined,
        is_staff: filters.is_staff || undefined,
        role: filters.role || undefined,
        department: filters.department || undefined,
      });
      setUsers(data.users);
      setPagination(data.pagination);
    } catch (err) {
      showMessage?.('Lỗi tải danh sách: ' + err.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleViewUser = async (userId) => {
    try {
      const data = await getAdminUser(userId);
      setUserDetail(data);
      setShowModal('view');
    } catch (err) {
      showMessage?.('Lỗi: ' + err.message, 'error');
    }
  };

  const handleEditUser = async (userId) => {
    try {
      const data = await getAdminUser(userId);
      setSelectedUser(data);
      setShowModal('edit');
    } catch (err) {
      showMessage?.('Lỗi: ' + err.message, 'error');
    }
  };

  const handleDeleteUser = (user) => {
    setSelectedUser(user);
    setShowModal('delete');
  };

  const handleResetPassword = async (userId) => {
    if (!confirm('Bạn có chắc muốn đặt lại mật khẩu cho người dùng này?')) return;
    
    try {
      const result = await adminResetUserPassword(userId);
      showMessage?.(`Mật khẩu mới: ${result.temp_password}`, 'success');
    } catch (err) {
      showMessage?.('Lỗi: ' + err.message, 'error');
    }
  };

  const confirmDelete = async (hardDelete = false) => {
    try {
      await deleteAdminUser(selectedUser.id, hardDelete);
      showMessage?.(hardDelete ? 'Đã xóa vĩnh viễn người dùng' : 'Đã vô hiệu hóa người dùng', 'success');
      setShowModal(null);
      loadUsers();
    } catch (err) {
      showMessage?.('Lỗi: ' + err.message, 'error');
    }
  };

  return (
    <div className="users-tab">
      {/* Controls */}
      <div className="tab-controls">
        <div className="search-box">
          <Search size={18} />
          <input
            type="text"
            placeholder="Tìm kiếm username, email, họ tên..."
            value={filters.search}
            onChange={(e) => setFilters(f => ({ ...f, search: e.target.value }))}
          />
        </div>

        <div className="filter-group">
          <select
            value={filters.is_active}
            onChange={(e) => setFilters(f => ({ ...f, is_active: e.target.value }))}
          >
            <option value="">Tất cả trạng thái</option>
            <option value="true">Hoạt động</option>
            <option value="false">Vô hiệu</option>
          </select>

          <select
            value={filters.role}
            onChange={(e) => setFilters(f => ({ ...f, role: e.target.value }))}
          >
            <option value="">Tất cả vai trò</option>
            {meta.roles.map(r => (
              <option key={r.value} value={r.value}>{r.label}</option>
            ))}
          </select>

          <select
            value={filters.department}
            onChange={(e) => setFilters(f => ({ ...f, department: e.target.value }))}
          >
            <option value="">Tất cả khoa</option>
            {meta.departments.map(d => (
              <option key={d.value} value={d.value}>{d.label}</option>
            ))}
          </select>
        </div>

        <button className="btn-primary" onClick={() => setShowModal('create')}>
          <Plus size={18} />
          Tạo người dùng
        </button>
      </div>

      {/* Table */}
      {loading ? (
        <div className="loading-state">
          <RefreshCw size={24} className="spinning" />
        </div>
      ) : (
        <>
          <div className="data-table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Người dùng</th>
                  <th>Vai trò</th>
                  <th>Khoa</th>
                  <th>Trạng thái</th>
                  <th>Chứng chỉ</th>
                  <th>Ngày tạo</th>
                  <th>Hành động</th>
                </tr>
              </thead>
              <tbody>
                {users.map(user => (
                  <tr key={user.id}>
                    <td className="user-cell">
                      <div className="user-avatar">{user.username.charAt(0).toUpperCase()}</div>
                      <div className="user-info">
                        <span className="user-name">
                          {user.username}
                          {user.is_staff && <span className="admin-badge">Admin</span>}
                        </span>
                        <span className="user-email">{user.profile?.full_name || user.email || '-'}</span>
                      </div>
                    </td>
                    <td>{user.profile?.role_display || 'Student'}</td>
                    <td className="dept-cell">{user.profile?.department_display || '-'}</td>
                    <td>
                      <span className={`status-badge ${user.is_active ? 'active' : 'inactive'}`}>
                        {user.is_active ? 'Hoạt động' : 'Vô hiệu'}
                      </span>
                    </td>
                    <td>{user.active_certificates}</td>
                    <td className="date-cell">{formatDate(user.date_joined)}</td>
                    <td className="actions-cell">
                      <button title="Xem" onClick={() => handleViewUser(user.id)}><Eye size={16} /></button>
                      <button title="Sửa" onClick={() => handleEditUser(user.id)}><Edit size={16} /></button>
                      <button title="Đặt lại mật khẩu" onClick={() => handleResetPassword(user.id)}><Key size={16} /></button>
                      <button title="Xóa" className="danger" onClick={() => handleDeleteUser(user)}><Trash2 size={16} /></button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <Pagination pagination={pagination} onChange={(page) => setPagination(p => ({ ...p, page }))} />
        </>
      )}

      {/* Modals */}
      {showModal === 'create' && (
        <UserFormModal
          mode="create"
          meta={meta}
          onClose={() => setShowModal(null)}
          onSuccess={() => { setShowModal(null); loadUsers(); }}
          showMessage={showMessage}
        />
      )}

      {showModal === 'edit' && selectedUser && (
        <UserFormModal
          mode="edit"
          user={selectedUser}
          meta={meta}
          onClose={() => setShowModal(null)}
          onSuccess={() => { setShowModal(null); loadUsers(); }}
          showMessage={showMessage}
        />
      )}

      {showModal === 'view' && userDetail && (
        <UserViewModal
          data={userDetail}
          onClose={() => setShowModal(null)}
        />
      )}

      {showModal === 'delete' && selectedUser && (
        <ConfirmModal
          title="Xóa người dùng"
          message={`Bạn có chắc muốn xóa người dùng "${selectedUser.username}"?`}
          onCancel={() => setShowModal(null)}
          onConfirm={() => confirmDelete(false)}
          onHardDelete={() => confirmDelete(true)}
          showHardDelete={true}
        />
      )}
    </div>
  );
}

// =============================================================================
// CERTIFICATES TAB
// =============================================================================

function CertificatesTab({ meta, showMessage }) {
  const [certificates, setCertificates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [pagination, setPagination] = useState({ page: 1, total_pages: 1 });
  const [filters, setFilters] = useState({ search: '', status: '' });
  const [showModal, setShowModal] = useState(null);
  const [selectedCert, setSelectedCert] = useState(null);

  useEffect(() => {
    loadCertificates();
  }, [pagination.page, filters.status]);

  useEffect(() => {
    const timer = setTimeout(() => {
      if (pagination.page === 1) loadCertificates();
      else setPagination(p => ({ ...p, page: 1 }));
    }, 300);
    return () => clearTimeout(timer);
  }, [filters.search]);

  const loadCertificates = async () => {
    try {
      setLoading(true);
      const data = await getAdminCertificates({
        page: pagination.page,
        per_page: 15,
        search: filters.search || undefined,
        status: filters.status || undefined,
      });
      setCertificates(data.certificates);
      setPagination(data.pagination);
    } catch (err) {
      showMessage?.('Lỗi: ' + err.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleRevoke = (cert) => {
    setSelectedCert(cert);
    setShowModal('revoke');
  };

  const confirmRevoke = async (reason) => {
    try {
      await adminRevokeCertificate(selectedCert.id, reason);
      showMessage?.('Đã thu hồi chứng chỉ', 'success');
      setShowModal(null);
      loadCertificates();
    } catch (err) {
      showMessage?.('Lỗi: ' + err.message, 'error');
    }
  };

  return (
    <div className="certificates-tab">
      <div className="tab-controls">
        <div className="search-box">
          <Search size={18} />
          <input
            type="text"
            placeholder="Tìm kiếm username, CN, serial..."
            value={filters.search}
            onChange={(e) => setFilters(f => ({ ...f, search: e.target.value }))}
          />
        </div>

        <div className="filter-group">
          <select
            value={filters.status}
            onChange={(e) => setFilters(f => ({ ...f, status: e.target.value }))}
          >
            <option value="">Tất cả trạng thái</option>
            <option value="valid">Hoạt động</option>
            <option value="revoked">Đã thu hồi</option>
            <option value="expired">Hết hạn</option>
            <option value="expiring_soon">Sắp hết hạn</option>
          </select>
        </div>

        <button className="refresh-btn" onClick={loadCertificates}>
          <RefreshCw size={16} />
          Làm mới
        </button>
      </div>

      {loading ? (
        <div className="loading-state"><RefreshCw size={24} className="spinning" /></div>
      ) : (
        <>
          <div className="data-table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Common Name</th>
                  <th>Serial Number</th>
                  <th>Trạng thái</th>
                  <th>Hiệu lực từ</th>
                  <th>Hết hạn</th>
                  <th>Hành động</th>
                </tr>
              </thead>
              <tbody>
                {certificates.map(cert => (
                  <tr key={cert.id} className={!cert.active ? 'row-revoked' : ''}>
                    <td>{cert.username}</td>
                    <td>{cert.common_name}</td>
                    <td className="serial-cell" title={cert.serial_number}>
                      {cert.serial_number ? cert.serial_number.substring(0, 16) + '...' : '-'}
                    </td>
                    <td><CertStatusBadge status={cert.status} /></td>
                    <td className="date-cell">{cert.valid_from ? formatDate(cert.valid_from) : formatDate(cert.created_at)}</td>
                    <td className="date-cell">{cert.expires_at ? formatDate(cert.expires_at) : '-'}</td>
                    <td className="actions-cell">
                      {cert.active && (
                        <button title="Thu hồi" className="danger" onClick={() => handleRevoke(cert)}>
                          <XCircle size={16} />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination pagination={pagination} onChange={(page) => setPagination(p => ({ ...p, page }))} />
        </>
      )}

      {showModal === 'revoke' && selectedCert && (
        <RevokeModal
          title="Thu hồi chứng chỉ"
          itemName={`${selectedCert.username} - ${selectedCert.common_name}`}
          reasons={meta.certificate_revocation_reasons || []}
          onCancel={() => setShowModal(null)}
          onConfirm={confirmRevoke}
        />
      )}
    </div>
  );
}

// =============================================================================
// SIGNING HISTORY TAB
// =============================================================================

function SigningHistoryTab({ showMessage }) {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [pagination, setPagination] = useState({ page: 1, total_pages: 1 });
  const [filters, setFilters] = useState({ search: '', status: '' });
  const [showModal, setShowModal] = useState(null);
  const [selectedItem, setSelectedItem] = useState(null);

  useEffect(() => {
    loadHistory();
  }, [pagination.page, filters.status]);

  useEffect(() => {
    const timer = setTimeout(() => {
      if (pagination.page === 1) loadHistory();
      else setPagination(p => ({ ...p, page: 1 }));
    }, 300);
    return () => clearTimeout(timer);
  }, [filters.search]);

  const loadHistory = async () => {
    try {
      setLoading(true);
      const data = await getAdminSigningHistory({
        page: pagination.page,
        per_page: 15,
        search: filters.search || undefined,
        status: filters.status || undefined,
      });
      setHistory(data.history);
      setPagination(data.pagination);
    } catch (err) {
      showMessage?.('Lỗi: ' + err.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleRevoke = (item) => {
    setSelectedItem(item);
    setShowModal('revoke');
  };

  const confirmRevoke = async () => {
    try {
      await adminRevokeSignature(selectedItem.id);
      showMessage?.('Đã thu hồi chữ ký', 'success');
      setShowModal(null);
      loadHistory();
    } catch (err) {
      showMessage?.('Lỗi: ' + err.message, 'error');
    }
  };

  return (
    <div className="history-tab">
      <div className="tab-controls">
        <div className="search-box">
          <Search size={18} />
          <input
            type="text"
            placeholder="Tìm kiếm username, tên tài liệu..."
            value={filters.search}
            onChange={(e) => setFilters(f => ({ ...f, search: e.target.value }))}
          />
        </div>

        <div className="filter-group">
          <select
            value={filters.status}
            onChange={(e) => setFilters(f => ({ ...f, status: e.target.value }))}
          >
            <option value="">Tất cả trạng thái</option>
            <option value="valid">Hợp lệ</option>
            <option value="revoked">Đã thu hồi</option>
            <option value="expired">Hết hạn</option>
          </select>
        </div>

        <button className="refresh-btn" onClick={loadHistory}>
          <RefreshCw size={16} />
          Làm mới
        </button>
      </div>

      {loading ? (
        <div className="loading-state"><RefreshCw size={24} className="spinning" /></div>
      ) : (
        <>
          <div className="data-table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Tên tài liệu</th>
                  <th>Trạng thái</th>
                  <th>Chứng chỉ</th>
                  <th>Thời gian ký</th>
                  <th>IP</th>
                  <th>Hành động</th>
                </tr>
              </thead>
              <tbody>
                {history.map(item => (
                  <tr key={item.id}>
                    <td>{item.username}</td>
                    <td className="doc-name-cell" title={item.document_name}>
                      {item.document_name.length > 30 
                        ? item.document_name.substring(0, 30) + '...' 
                        : item.document_name}
                    </td>
                    <td><StatusBadge status={item.status} /></td>
                    <td>{item.certificate_cn || '-'}</td>
                    <td className="date-cell">{formatDateTime(item.signed_at)}</td>
                    <td className="ip-cell">{item.ip_address || '-'}</td>
                    <td className="actions-cell">
                      {item.status === 'valid' && (
                        <button title="Thu hồi" className="danger" onClick={() => handleRevoke(item)}>
                          <XCircle size={16} />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination pagination={pagination} onChange={(page) => setPagination(p => ({ ...p, page }))} />
        </>
      )}

      {showModal === 'revoke' && selectedItem && (
        <ConfirmModal
          title="Thu hồi chữ ký"
          message={`Bạn có chắc muốn thu hồi chữ ký cho tài liệu "${selectedItem.document_name}"?`}
          onCancel={() => setShowModal(null)}
          onConfirm={confirmRevoke}
        />
      )}
    </div>
  );
}

// =============================================================================
// MODALS
// =============================================================================

function UserFormModal({ mode, user, meta, onClose, onSuccess, showMessage }) {
  const [formData, setFormData] = useState({
    username: '',
    password: '',
    email: '',
    is_active: true,
    is_staff: false,
    profile: {
      full_name: '',
      phone: '',
      role: 'student',
      department: '',
      notes: ''
    }
  });
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (mode === 'edit' && user) {
      setFormData({
        username: user.user.username,
        email: user.user.email || '',
        is_active: user.user.is_active,
        is_staff: user.user.is_staff,
        profile: {
          full_name: user.profile?.full_name || '',
          phone: user.profile?.phone || '',
          role: user.profile?.role || 'student',
          department: user.profile?.department || '',
          notes: user.profile?.notes || ''
        }
      });
    }
  }, [mode, user]);

  const validate = () => {
    const newErrors = {};
    if (mode === 'create') {
      if (!formData.username.trim()) newErrors.username = 'Username là bắt buộc';
      if (!formData.password || formData.password.length < 8) {
        newErrors.password = 'Mật khẩu phải có ít nhất 8 ký tự';
      }
    }
    if (formData.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      newErrors.email = 'Email không hợp lệ';
    }
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!validate()) return;

    try {
      setLoading(true);
      if (mode === 'create') {
        await createAdminUser(formData);
        showMessage?.('Tạo người dùng thành công!', 'success');
      } else {
        const updateData = {
          email: formData.email,
          is_active: formData.is_active,
          is_staff: formData.is_staff,
          profile: formData.profile
        };
        await updateAdminUser(user.user.id, updateData);
        showMessage?.('Cập nhật thành công!', 'success');
      }
      onSuccess();
    } catch (err) {
      showMessage?.('Lỗi: ' + err.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content large" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h3>{mode === 'create' ? 'Tạo người dùng mới' : 'Chỉnh sửa người dùng'}</h3>
          <button className="close-btn" onClick={onClose}>&times;</button>
        </div>
        
        <form onSubmit={handleSubmit} className="modal-form">
          <div className="form-grid">
            {mode === 'create' && (
              <>
                <div className="form-group">
                  <label>Username *</label>
                  <input
                    type="text"
                    value={formData.username}
                    onChange={(e) => setFormData(f => ({ ...f, username: e.target.value }))}
                    className={errors.username ? 'error' : ''}
                  />
                  {errors.username && <span className="error-text">{errors.username}</span>}
                </div>
                <div className="form-group">
                  <label>Mật khẩu *</label>
                  <input
                    type="password"
                    value={formData.password}
                    onChange={(e) => setFormData(f => ({ ...f, password: e.target.value }))}
                    className={errors.password ? 'error' : ''}
                  />
                  {errors.password && <span className="error-text">{errors.password}</span>}
                </div>
              </>
            )}
            
            <div className="form-group">
              <label>Email</label>
              <input
                type="email"
                value={formData.email}
                onChange={(e) => setFormData(f => ({ ...f, email: e.target.value }))}
                className={errors.email ? 'error' : ''}
              />
              {errors.email && <span className="error-text">{errors.email}</span>}
            </div>

            <div className="form-group">
              <label>Họ và tên</label>
              <input
                type="text"
                value={formData.profile.full_name}
                onChange={(e) => setFormData(f => ({ 
                  ...f, 
                  profile: { ...f.profile, full_name: e.target.value }
                }))}
              />
            </div>

            <div className="form-group">
              <label>Số điện thoại</label>
              <input
                type="text"
                value={formData.profile.phone}
                onChange={(e) => setFormData(f => ({ 
                  ...f, 
                  profile: { ...f.profile, phone: e.target.value }
                }))}
              />
            </div>

            <div className="form-group">
              <label>Vai trò</label>
              <select
                value={formData.profile.role}
                onChange={(e) => setFormData(f => ({ 
                  ...f, 
                  profile: { ...f.profile, role: e.target.value }
                }))}
              >
                {meta.roles.map(r => (
                  <option key={r.value} value={r.value}>{r.label}</option>
                ))}
              </select>
            </div>

            <div className="form-group">
              <label>Khoa/Phòng ban</label>
              <select
                value={formData.profile.department}
                onChange={(e) => setFormData(f => ({ 
                  ...f, 
                  profile: { ...f.profile, department: e.target.value }
                }))}
              >
                <option value="">-- Chọn khoa --</option>
                {meta.departments.map(d => (
                  <option key={d.value} value={d.value}>{d.label}</option>
                ))}
              </select>
            </div>

            <div className="form-group full-width">
              <label>Ghi chú</label>
              <textarea
                value={formData.profile.notes}
                onChange={(e) => setFormData(f => ({ 
                  ...f, 
                  profile: { ...f.profile, notes: e.target.value }
                }))}
                rows={3}
              />
            </div>

            <div className="form-group checkbox-group">
              <label>
                <input
                  type="checkbox"
                  checked={formData.is_active}
                  onChange={(e) => setFormData(f => ({ ...f, is_active: e.target.checked }))}
                />
                Hoạt động
              </label>
              <label>
                <input
                  type="checkbox"
                  checked={formData.is_staff}
                  onChange={(e) => setFormData(f => ({ ...f, is_staff: e.target.checked }))}
                />
                Quyền Admin
              </label>
            </div>
          </div>

          <div className="modal-actions">
            <button type="button" className="btn-secondary" onClick={onClose}>Hủy</button>
            <button type="submit" className="btn-primary" disabled={loading}>
              {loading ? 'Đang xử lý...' : (mode === 'create' ? 'Tạo người dùng' : 'Cập nhật')}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function UserViewModal({ data, onClose }) {
  const { user, profile, certificates, signing_count } = data;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content large" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h3>Chi tiết người dùng</h3>
          <button className="close-btn" onClick={onClose}>&times;</button>
        </div>
        
        <div className="user-detail-view">
          <div className="detail-section">
            <h4>Thông tin tài khoản</h4>
            <div className="detail-grid">
              <div className="detail-item">
                <span className="detail-label">Username</span>
                <span className="detail-value">{user.username}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Email</span>
                <span className="detail-value">{user.email || '-'}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Trạng thái</span>
                <span className={`status-badge ${user.is_active ? 'active' : 'inactive'}`}>
                  {user.is_active ? 'Hoạt động' : 'Vô hiệu'}
                </span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Quyền Admin</span>
                <span className={`status-badge ${user.is_staff ? 'admin' : ''}`}>
                  {user.is_staff ? 'Có' : 'Không'}
                </span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Ngày tạo</span>
                <span className="detail-value">{formatDateTime(user.date_joined)}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Đăng nhập cuối</span>
                <span className="detail-value">{user.last_login ? formatDateTime(user.last_login) : 'Chưa đăng nhập'}</span>
              </div>
            </div>
          </div>

          {profile && (
            <div className="detail-section">
              <h4>Thông tin cá nhân</h4>
              <div className="detail-grid">
                <div className="detail-item">
                  <span className="detail-label">Họ và tên</span>
                  <span className="detail-value">{profile.full_name || '-'}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">Số điện thoại</span>
                  <span className="detail-value">{profile.phone || '-'}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">Vai trò</span>
                  <span className="detail-value">{profile.role_display}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">Khoa/Phòng ban</span>
                  <span className="detail-value">{profile.department_display || '-'}</span>
                </div>
                {profile.notes && (
                  <div className="detail-item full-width">
                    <span className="detail-label">Ghi chú</span>
                    <span className="detail-value">{profile.notes}</span>
                  </div>
                )}
              </div>
            </div>
          )}

          <div className="detail-section">
            <h4>Chứng chỉ ({certificates.length})</h4>
            {certificates.length > 0 ? (
              <div className="mini-table">
                <table>
                  <thead>
                    <tr>
                      <th>Common Name</th>
                      <th>Trạng thái</th>
                      <th>Ngày tạo</th>
                      <th>Hết hạn</th>
                    </tr>
                  </thead>
                  <tbody>
                    {certificates.map(cert => (
                      <tr key={cert.id}>
                        <td>{cert.common_name}</td>
                        <td>
                          <span className={`status-badge ${cert.active ? 'active' : 'revoked'}`}>
                            {cert.active ? 'Hoạt động' : 'Thu hồi'}
                          </span>
                        </td>
                        <td>{formatDate(cert.created_at)}</td>
                        <td>{cert.expires_at ? formatDate(cert.expires_at) : '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="no-data">Chưa có chứng chỉ</p>
            )}
          </div>

          <div className="detail-section">
            <h4>Thống kê ký số</h4>
            <p className="stat-text">Tổng số lần ký: <strong>{signing_count}</strong></p>
          </div>
        </div>

        <div className="modal-actions">
          <button className="btn-secondary" onClick={onClose}>Đóng</button>
        </div>
      </div>
    </div>
  );
}

function ConfirmModal({ title, message, onCancel, onConfirm, onHardDelete, showHardDelete }) {
  return (
    <div className="modal-overlay" onClick={onCancel}>
      <div className="modal-content confirm" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h3>{title}</h3>
          <button className="close-btn" onClick={onCancel}>&times;</button>
        </div>
        <div className="modal-body">
          <AlertTriangle size={48} className="warning-icon" />
          <p>{message}</p>
        </div>
        <div className="modal-actions">
          <button className="btn-secondary" onClick={onCancel}>Hủy</button>
          <button className="btn-warning" onClick={onConfirm}>
            {showHardDelete ? 'Vô hiệu hóa' : 'Xác nhận'}
          </button>
          {showHardDelete && (
            <button className="btn-danger" onClick={onHardDelete}>
              Xóa vĩnh viễn
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function RevokeModal({ title, itemName, reasons, onCancel, onConfirm }) {
  const [reason, setReason] = useState('unspecified');

  return (
    <div className="modal-overlay" onClick={onCancel}>
      <div className="modal-content" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h3>{title}</h3>
          <button className="close-btn" onClick={onCancel}>&times;</button>
        </div>
        <div className="modal-body">
          <p>Thu hồi: <strong>{itemName}</strong></p>
          <div className="form-group">
            <label>Lý do thu hồi</label>
            <select value={reason} onChange={(e) => setReason(e.target.value)}>
              {reasons.map(r => (
                <option key={r.value} value={r.value}>{r.label}</option>
              ))}
            </select>
          </div>
        </div>
        <div className="modal-actions">
          <button className="btn-secondary" onClick={onCancel}>Hủy</button>
          <button className="btn-danger" onClick={() => onConfirm(reason)}>Thu hồi</button>
        </div>
      </div>
    </div>
  );
}

// =============================================================================
// HELPER COMPONENTS
// =============================================================================

function Pagination({ pagination, onChange }) {
  const { page, total_pages, total } = pagination;
  
  return (
    <div className="pagination">
      <span className="pagination-info">Tổng: {total} bản ghi</span>
      <div className="pagination-controls">
        <button 
          disabled={page <= 1} 
          onClick={() => onChange(page - 1)}
        >
          <ChevronLeft size={16} />
        </button>
        <span>Trang {page} / {total_pages}</span>
        <button 
          disabled={page >= total_pages} 
          onClick={() => onChange(page + 1)}
        >
          <ChevronRight size={16} />
        </button>
      </div>
    </div>
  );
}

function StatusBadge({ status }) {
  const config = {
    valid: { icon: CheckCircle, text: 'Hợp lệ', className: 'valid' },
    revoked: { icon: XCircle, text: 'Thu hồi', className: 'revoked' },
    expired: { icon: AlertTriangle, text: 'Hết hạn', className: 'expired' },
    deleted: { icon: Trash2, text: 'Đã xóa', className: 'deleted' },
    invalid: { icon: XCircle, text: 'Không hợp lệ', className: 'invalid' },
  };
  const { icon: Icon, text, className } = config[status] || config.invalid;
  
  return (
    <span className={`status-badge ${className}`}>
      <Icon size={12} />
      {text}
    </span>
  );
}

function CertStatusBadge({ status }) {
  const config = {
    active: { text: 'Hoạt động', className: 'active' },
    valid: { text: 'Hoạt động', className: 'active' },
    revoked: { text: 'Thu hồi', className: 'revoked' },
    expired: { text: 'Hết hạn', className: 'expired' },
    expiring: { text: 'Sắp hết hạn', className: 'warning' },
    expiring_soon: { text: 'Sắp hết hạn', className: 'warning' },
  };
  const { text, className } = config[status] || config.active;
  
  return <span className={`status-badge ${className}`}>{text}</span>;
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

function formatDate(dateString) {
  if (!dateString) return '-';
  return new Date(dateString).toLocaleDateString('vi-VN');
}

function formatDateTime(dateString) {
  if (!dateString) return '-';
  return new Date(dateString).toLocaleString('vi-VN');
}
