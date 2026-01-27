import React, { useState, useEffect } from 'react';
import {
  Award,
  Search,
  Filter,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  X,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Clock,
  RotateCcw,
  Ban,
  Eye
} from 'lucide-react';
import { 
  getAdminCertificates, 
  adminRevokeCertificate, 
  adminRenewCertificate 
} from '../../api';
import ConfirmDialog from './ConfirmDialog';
import CertificateDetailModal from './CertificateDetailModal';
import '../../static/styles/admin.css';

/**
 * AdminCertificatesTab Component
 * 
 * Certificate management:
 * - List all certificates
 * - Filter by status
 * - Renew certificates
 * - Revoke certificates
 */
export default function AdminCertificatesTab({ showMessage }) {
  const [certificates, setCertificates] = useState([]);
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
  const [filterStatus, setFilterStatus] = useState('');
  const [showFilters, setShowFilters] = useState(false);
  
  // Modals
  const [showDetailModal, setShowDetailModal] = useState(false);
  const [showRevokeConfirm, setShowRevokeConfirm] = useState(false);
  const [showRenewConfirm, setShowRenewConfirm] = useState(false);
  const [selectedCert, setSelectedCert] = useState(null);
  const [revokeReason, setRevokeReason] = useState('unspecified');

  useEffect(() => {
    loadCertificates();
  }, [pagination.page, search, filterStatus]);

  const loadCertificates = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const params = {
        page: pagination.page,
        per_page: pagination.perPage,
        search,
        status: filterStatus
      };
      
      const data = await getAdminCertificates(params);
      setCertificates(data.certificates || []);
      setPagination(prev => ({
        ...prev,
        total: data.pagination?.total || 0,
        totalPages: data.pagination?.total_pages || 0
      }));
    } catch (err) {
      setError('Không thể tải danh sách chứng chỉ: ' + (err.message || err));
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = (e) => {
    setSearch(e.target.value);
    setPagination(prev => ({ ...prev, page: 1 }));
  };

  const handleRevoke = async () => {
    try {
      await adminRevokeCertificate(selectedCert.id, revokeReason);
      showMessage('Thu hồi chứng chỉ thành công!', 'success');
      setShowRevokeConfirm(false);
      setSelectedCert(null);
      setRevokeReason('unspecified');
      loadCertificates();
    } catch (err) {
      showMessage('Lỗi thu hồi chứng chỉ: ' + (err.message || err), 'error');
    }
  };

  const handleRenew = async () => {
    try {
      await adminRenewCertificate(selectedCert.id);
      showMessage('Gia hạn chứng chỉ thành công!', 'success');
      setShowRenewConfirm(false);
      setSelectedCert(null);
      loadCertificates();
    } catch (err) {
      showMessage('Lỗi gia hạn chứng chỉ: ' + (err.message || err), 'error');
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'active':
        return <CheckCircle size={14} />;
      case 'revoked':
        return <XCircle size={14} />;
      case 'expired':
        return <XCircle size={14} />;
      case 'expiring':
        return <AlertTriangle size={14} />;
      default:
        return <Clock size={14} />;
    }
  };

  const getStatusLabel = (status) => {
    switch (status) {
      case 'active':
        return 'Hợp lệ';
      case 'revoked':
        return 'Thu hồi';
      case 'expired':
        return 'Hết hạn';
      case 'expiring':
        return 'Sắp hết hạn';
      default:
        return status;
    }
  };

  const clearFilters = () => {
    setFilterStatus('');
    setSearch('');
    setPagination(prev => ({ ...prev, page: 1 }));
  };

  const hasActiveFilters = filterStatus || search;

  return (
    <div className="admin-tab-content">
      {/* Toolbar */}
      <div className="admin-toolbar">
        <div className="toolbar-left">
          <div className="search-box">
            <Search size={18} />
            <input
              type="text"
              placeholder="Tìm kiếm chứng chỉ..."
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
          <button className="btn-refresh" onClick={loadCertificates} disabled={loading}>
            <RefreshCw size={18} className={loading ? 'spinning' : ''} />
          </button>
        </div>
      </div>

      {/* Filters Panel */}
      {showFilters && (
        <div className="filters-panel">
          <div className="filter-group">
            <label>Trạng thái</label>
            <select value={filterStatus} onChange={(e) => { setFilterStatus(e.target.value); setPagination(prev => ({ ...prev, page: 1 })); }}>
              <option value="">Tất cả</option>
              <option value="active">Hợp lệ</option>
              <option value="expiring">Sắp hết hạn</option>
              <option value="expired">Hết hạn</option>
              <option value="revoked">Thu hồi</option>
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
          <button onClick={loadCertificates}>Thử lại</button>
        </div>
      )}

      {/* Table */}
      <div className="admin-table-container">
        <table className="admin-table">
          <thead>
            <tr>
              <th>Người dùng</th>
              <th>Tên chứng chỉ (CN)</th>
              <th>Số sê-ri</th>
              <th>Trạng thái</th>
              <th>Ngày tạo</th>
              <th>Ngày hết hạn</th>
              <th>Còn lại</th>
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
            ) : certificates.length === 0 ? (
              <tr>
                <td colSpan="8" className="empty-cell">
                  <Award size={32} />
                  <span>Không có chứng chỉ nào</span>
                </td>
              </tr>
            ) : (
              certificates.map(cert => (
                <tr key={cert.id} className={cert.status === 'revoked' ? 'row-revoked' : ''}>
                  <td>
                    <div className="user-cell">
                      <div className="user-avatar">
                        {cert.username?.charAt(0).toUpperCase() || '?'}
                      </div>
                      <div className="user-info">
                        <span className="user-name">{cert.full_name || cert.username}</span>
                        <span className="user-username">@{cert.username}</span>
                      </div>
                    </div>
                  </td>
                  <td>{cert.common_name || '-'}</td>
                  <td>
                    <code className="serial-number">{cert.serial_number?.substring(0, 16) || '-'}...</code>
                  </td>
                  <td>
                    <span className={`status-badge ${cert.status}`}>
                      {getStatusIcon(cert.status)}
                      {getStatusLabel(cert.status)}
                    </span>
                  </td>
                  <td>{cert.created_at ? new Date(cert.created_at).toLocaleDateString('vi-VN') : '-'}</td>
                  <td>{cert.expires_at ? new Date(cert.expires_at).toLocaleDateString('vi-VN') : '-'}</td>
                  <td>
                    {cert.status === 'revoked' ? (
                      <span className="days-badge revoked">-</span>
                    ) : cert.days_remaining <= 0 ? (
                      <span className="days-badge expired">Hết hạn</span>
                    ) : cert.days_remaining <= 30 ? (
                      <span className="days-badge warning">{cert.days_remaining} ngày</span>
                    ) : (
                      <span className="days-badge">{cert.days_remaining} ngày</span>
                    )}
                  </td>
                  <td>
                    <div className="action-buttons">
                      <button 
                        className="btn-action view" 
                        onClick={() => { setSelectedCert(cert); setShowDetailModal(true); }}
                        title="Xem chi tiết"
                      >
                        <Eye size={16} />
                      </button>
                      {cert.active && (
                        <>
                          <button 
                            className="btn-action renew" 
                            onClick={() => { setSelectedCert(cert); setShowRenewConfirm(true); }}
                            title="Gia hạn"
                          >
                            <RotateCcw size={16} />
                          </button>
                          <button 
                            className="btn-action revoke" 
                            onClick={() => { setSelectedCert(cert); setShowRevokeConfirm(true); }}
                            title="Thu hồi"
                          >
                            <Ban size={16} />
                          </button>
                        </>
                      )}
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
            Hiển thị {certificates.length} / {pagination.total} chứng chỉ
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

      {/* Detail Modal */}
      {showDetailModal && selectedCert && (
        <CertificateDetailModal
          certificate={selectedCert}
          onClose={() => { setShowDetailModal(false); setSelectedCert(null); }}
          onRenew={() => {
            setShowDetailModal(false);
            setShowRenewConfirm(true);
          }}
          onRevoke={() => {
            setShowDetailModal(false);
            setShowRevokeConfirm(true);
          }}
        />
      )}

      {/* Revoke Confirmation */}
      {showRevokeConfirm && selectedCert && (
        <div className="modal-overlay" onClick={() => { setShowRevokeConfirm(false); setSelectedCert(null); }}>
          <div className="modal-content confirm-dialog" onClick={e => e.stopPropagation()}>
            <div className="dialog-header danger">
              <Ban size={24} />
              <h3>Thu hồi chứng chỉ</h3>
            </div>
            <div className="dialog-body">
              <p>
                Bạn có chắc muốn thu hồi chứng chỉ của <strong>{selectedCert.username}</strong>?
              </p>
              <p className="warning-text">
                Tất cả chữ ký số sử dụng chứng chỉ này sẽ bị đánh dấu thu hồi.
              </p>
              <div className="form-group">
                <label>Lý do thu hồi</label>
                <select value={revokeReason} onChange={(e) => setRevokeReason(e.target.value)}>
                  <option value="unspecified">Không xác định</option>
                  <option value="key_compromise">Key Compromise</option>
                  <option value="affiliation_changed">Affiliation Changed</option>
                  <option value="superseded">Superseded</option>
                  <option value="cessation_of_operation">Cessation of Operation</option>
                  <option value="privilege_withdrawn">Privilege Withdrawn</option>
                </select>
              </div>
            </div>
            <div className="dialog-footer">
              <button className="btn-cancel" onClick={() => { setShowRevokeConfirm(false); setSelectedCert(null); }}>
                Hủy
              </button>
              <button className="btn-danger" onClick={handleRevoke}>
                Thu hồi
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Renew Confirmation */}
      {showRenewConfirm && selectedCert && (
        <ConfirmDialog
          title="Gia hạn chứng chỉ"
          message={`Bạn có chắc muốn gia hạn chứng chỉ của "${selectedCert.username}"? Chứng chỉ cũ sẽ bị thu hồi và thay thế bằng chứng chỉ mới.`}
          confirmText="Gia hạn"
          confirmType="primary"
          onConfirm={handleRenew}
          onCancel={() => { setShowRenewConfirm(false); setSelectedCert(null); }}
        />
      )}
    </div>
  );
}
