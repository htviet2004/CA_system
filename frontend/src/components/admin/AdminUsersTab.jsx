import React, { useState, useEffect, useCallback } from 'react';
import {
  Users,
  Plus,
  Search,
  Filter,
  Edit,
  Trash2,
  Eye,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  X,
  CheckCircle,
  XCircle,
  Shield,
  Award
} from 'lucide-react';
import { 
  getAdminUsers, 
  getAdminUser, 
  createAdminUser, 
  updateAdminUser, 
  deleteAdminUser,
  getAdminMeta,
  adminReissueCertificate 
} from '../../api';
import UserFormModal from './UserFormModal';
import ConfirmDialog from './ConfirmDialog';
import UserDetailModal from './UserDetailModal';
import '../../static/styles/admin.css';

/**
 * AdminUsersTab Component
 * 
 * Full CRUD for user management:
 * - List users with pagination
 * - Search and filter
 * - Create new user
 * - Edit user
 * - Delete user
 * - View user details
 */
export default function AdminUsersTab({ showMessage }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  // Pagination
  const [pagination, setPagination] = useState({
    page: 1,
    perPage: 10,
    total: 0,
    totalPages: 0
  });
  
  // Filters
  const [search, setSearch] = useState('');
  const [filterActive, setFilterActive] = useState('');
  const [filterRole, setFilterRole] = useState('');
  const [filterDepartment, setFilterDepartment] = useState('');
  const [showFilters, setShowFilters] = useState(false);
  
  // Modals
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showDetailModal, setShowDetailModal] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [selectedUser, setSelectedUser] = useState(null);
  const [selectedUserDetail, setSelectedUserDetail] = useState(null);
  
  // Meta data (roles, departments)
  const [meta, setMeta] = useState({ roles: [], departments: [] });

  // Load meta data on mount
  useEffect(() => {
    loadMeta();
  }, []);

  // Load users when filters change
  useEffect(() => {
    loadUsers();
  }, [pagination.page, search, filterActive, filterRole, filterDepartment]);

  const loadMeta = async () => {
    try {
      const data = await getAdminMeta();
      setMeta(data);
    } catch (err) {
      console.error('Failed to load meta:', err);
    }
  };

  const loadUsers = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const params = {
        page: pagination.page,
        per_page: pagination.perPage,
        search,
        is_active: filterActive,
        role: filterRole,
        department: filterDepartment
      };
      
      const data = await getAdminUsers(params);
      setUsers(data.users || []);
      setPagination(prev => ({
        ...prev,
        total: data.pagination?.total || 0,
        totalPages: data.pagination?.total_pages || 0
      }));
    } catch (err) {
      setError('Không thể tải danh sách người dùng: ' + (err.message || err));
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = (e) => {
    setSearch(e.target.value);
    setPagination(prev => ({ ...prev, page: 1 }));
  };

  const handleCreate = async (userData) => {
    try {
      await createAdminUser(userData);
      showMessage('Tạo người dùng thành công!', 'success');
      setShowCreateModal(false);
      loadUsers();
    } catch (err) {
      throw err;
    }
  };

  const handleEdit = async (userData) => {
    try {
      await updateAdminUser(selectedUser.id, userData);
      showMessage('Cập nhật người dùng thành công!', 'success');
      setShowEditModal(false);
      setSelectedUser(null);
      loadUsers();
    } catch (err) {
      throw err;
    }
  };

  const handleDelete = async () => {
    try {
      await deleteAdminUser(selectedUser.id);
      showMessage('Xóa người dùng thành công!', 'success');
      setShowDeleteConfirm(false);
      setSelectedUser(null);
      loadUsers();
    } catch (err) {
      showMessage('Lỗi xóa người dùng: ' + (err.message || err), 'error');
    }
  };

  const handleViewDetail = async (user) => {
    try {
      const detail = await getAdminUser(user.id);
      setSelectedUserDetail(detail);
      setShowDetailModal(true);
    } catch (err) {
      showMessage('Không thể tải chi tiết người dùng: ' + (err.message || err), 'error');
    }
  };

  const handleReissueCert = async (userId, commonName) => {
    try {
      await adminReissueCertificate(userId, commonName);
      showMessage('Cấp lại chứng chỉ thành công!', 'success');
      // Reload user detail
      const detail = await getAdminUser(userId);
      setSelectedUserDetail(detail);
    } catch (err) {
      showMessage('Lỗi cấp lại chứng chỉ: ' + (err.message || err), 'error');
    }
  };

  const openEditModal = (user) => {
    setSelectedUser(user);
    setShowEditModal(true);
  };

  const openDeleteConfirm = (user) => {
    setSelectedUser(user);
    setShowDeleteConfirm(true);
  };

  const clearFilters = () => {
    setFilterActive('');
    setFilterRole('');
    setFilterDepartment('');
    setSearch('');
    setPagination(prev => ({ ...prev, page: 1 }));
  };

  const hasActiveFilters = filterActive || filterRole || filterDepartment || search;

  return (
    <div className="admin-tab-content">
      {/* Toolbar */}
      <div className="admin-toolbar">
        <div className="toolbar-left">
          <div className="search-box">
            <Search size={18} />
            <input
              type="text"
              placeholder="Tìm kiếm người dùng..."
              value={search}
              onChange={handleSearch}
            />
            {search && (
              <button className="clear-search" onClick={() => { setSearch(''); setPagination(prev => ({ ...prev, page: 1 })); }}>
                <X size={16} />
              </button>
            )}
          </div>
          <button 
            className={`btn-filter ${showFilters ? 'active' : ''}`}
            onClick={() => setShowFilters(!showFilters)}
          >
            <Filter size={18} />
            Lọc
            {hasActiveFilters && <span className="filter-badge" />}
          </button>
        </div>
        <div className="toolbar-right">
          <button className="btn-refresh" onClick={loadUsers} disabled={loading}>
            <RefreshCw size={18} className={loading ? 'spinning' : ''} />
          </button>
          <button className="btn-primary" onClick={() => setShowCreateModal(true)}>
            <Plus size={18} />
            Thêm người dùng
          </button>
        </div>
      </div>

      {/* Filters Panel */}
      {showFilters && (
        <div className="filters-panel">
          <div className="filter-group">
            <label>Trạng thái</label>
            <select value={filterActive} onChange={(e) => { setFilterActive(e.target.value); setPagination(prev => ({ ...prev, page: 1 })); }}>
              <option value="">Tất cả</option>
              <option value="true">Hoạt động</option>
              <option value="false">Đã khóa</option>
            </select>
          </div>
          <div className="filter-group">
            <label>Vai trò</label>
            <select value={filterRole} onChange={(e) => { setFilterRole(e.target.value); setPagination(prev => ({ ...prev, page: 1 })); }}>
              <option value="">Tất cả</option>
              {meta.roles?.map(r => (
                <option key={r.value} value={r.value}>{r.label}</option>
              ))}
            </select>
          </div>
          <div className="filter-group">
            <label>Khoa/Phòng</label>
            <select value={filterDepartment} onChange={(e) => { setFilterDepartment(e.target.value); setPagination(prev => ({ ...prev, page: 1 })); }}>
              <option value="">Tất cả</option>
              {meta.departments?.map(d => (
                <option key={d.value} value={d.value}>{d.label}</option>
              ))}
            </select>
          </div>
          {hasActiveFilters && (
            <button className="btn-clear-filters" onClick={clearFilters}>
              <X size={16} />
              Xóa bộ lọc
            </button>
          )}
        </div>
      )}

      {/* Error State */}
      {error && (
        <div className="admin-error-inline">
          <span>{error}</span>
          <button onClick={loadUsers}>Thử lại</button>
        </div>
      )}

      {/* Table */}
      <div className="admin-table-container">
        <table className="admin-table">
          <thead>
            <tr>
              <th>Người dùng</th>
              <th>Email</th>
              <th>Vai trò</th>
              <th>Khoa/Phòng</th>
              <th>Trạng thái</th>
              <th>Chứng chỉ</th>
              <th>Ngày tạo</th>
              <th>Thao tác</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan="8" className="loading-cell">
                  <RefreshCw size={24} className="spinning" />
                  <span>Đang tải...</span>
                </td>
              </tr>
            ) : users.length === 0 ? (
              <tr>
                <td colSpan="8" className="empty-cell">
                  <Users size={32} />
                  <span>Không có người dùng nào</span>
                </td>
              </tr>
            ) : (
              users.map(user => (
                <tr key={user.id}>
                  <td>
                    <div className="user-cell">
                      <div className="user-avatar">
                        {user.username.charAt(0).toUpperCase()}
                      </div>
                      <div className="user-info">
                        <span className="user-name">
                          {user.profile?.full_name || user.username}
                          {user.is_staff && <Shield size={14} className="admin-badge" title="Admin" />}
                        </span>
                        <span className="user-username">@{user.username}</span>
                      </div>
                    </div>
                  </td>
                  <td>{user.email || user.profile?.email || '-'}</td>
                  <td>
                    <span className={`role-badge ${user.profile?.role || 'student'}`}>
                      {user.profile?.role_display || 'Student'}
                    </span>
                  </td>
                  <td>{user.profile?.department_display || '-'}</td>
                  <td>
                    <span className={`status-badge ${user.is_active ? 'active' : 'inactive'}`}>
                      {user.is_active ? (
                        <>
                          <CheckCircle size={14} />
                          Hoạt động
                        </>
                      ) : (
                        <>
                          <XCircle size={14} />
                          Đã khóa
                        </>
                      )}
                    </span>
                  </td>
                  <td>
                    {user.active_certificates > 0 ? (
                      <span className="cert-badge active">
                        <Award size={14} />
                        {user.active_certificates}
                      </span>
                    ) : (
                      <span className="cert-badge none">Chưa có</span>
                    )}
                  </td>
                  <td>{new Date(user.date_joined).toLocaleDateString('vi-VN')}</td>
                  <td>
                    <div className="action-buttons">
                      <button 
                        className="btn-action view" 
                        onClick={() => handleViewDetail(user)}
                        title="Xem chi tiết"
                      >
                        <Eye size={16} />
                      </button>
                      <button 
                        className="btn-action edit" 
                        onClick={() => openEditModal(user)}
                        title="Chỉnh sửa"
                      >
                        <Edit size={16} />
                      </button>
                      <button 
                        className="btn-action delete" 
                        onClick={() => openDeleteConfirm(user)}
                        title="Xóa"
                        disabled={user.is_staff}
                      >
                        <Trash2 size={16} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {pagination.totalPages > 1 && (
        <div className="pagination">
          <span className="pagination-info">
            Hiển thị {users.length} / {pagination.total} người dùng
          </span>
          <div className="pagination-controls">
            <button
              className="btn-page"
              disabled={pagination.page <= 1}
              onClick={() => setPagination(prev => ({ ...prev, page: prev.page - 1 }))}
            >
              <ChevronLeft size={18} />
            </button>
            <span className="page-number">
              Trang {pagination.page} / {pagination.totalPages}
            </span>
            <button
              className="btn-page"
              disabled={pagination.page >= pagination.totalPages}
              onClick={() => setPagination(prev => ({ ...prev, page: prev.page + 1 }))}
            >
              <ChevronRight size={18} />
            </button>
          </div>
        </div>
      )}

      {/* Create Modal */}
      {showCreateModal && (
        <UserFormModal
          mode="create"
          meta={meta}
          onSubmit={handleCreate}
          onClose={() => setShowCreateModal(false)}
        />
      )}

      {/* Edit Modal */}
      {showEditModal && selectedUser && (
        <UserFormModal
          mode="edit"
          user={selectedUser}
          meta={meta}
          onSubmit={handleEdit}
          onClose={() => { setShowEditModal(false); setSelectedUser(null); }}
        />
      )}

      {/* Detail Modal */}
      {showDetailModal && selectedUserDetail && (
        <UserDetailModal
          user={selectedUserDetail}
          onClose={() => { setShowDetailModal(false); setSelectedUserDetail(null); }}
          onEdit={() => {
            setShowDetailModal(false);
            setSelectedUser(selectedUserDetail.user);
            setShowEditModal(true);
          }}
          onReissueCert={handleReissueCert}
        />
      )}

      {/* Delete Confirmation */}
      {showDeleteConfirm && selectedUser && (
        <ConfirmDialog
          title="Xác nhận xóa"
          message={`Bạn có chắc muốn xóa người dùng "${selectedUser.username}"? Hành động này không thể hoàn tác.`}
          confirmText="Xóa"
          confirmType="danger"
          onConfirm={handleDelete}
          onCancel={() => { setShowDeleteConfirm(false); setSelectedUser(null); }}
        />
      )}
    </div>
  );
}
