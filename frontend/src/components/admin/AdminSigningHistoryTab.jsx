import React, { useState, useEffect } from 'react';
import {
  FileText,
  Search,
  Filter,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  X,
  CheckCircle,
  XCircle,
  Eye,
  Download,
  Ban
} from 'lucide-react';
import { getAdminSigningHistory, adminRevokeSignature } from '../../api';
import ConfirmDialog from './ConfirmDialog';
import SignatureDetailModal from './SignatureDetailModal';
import '../../static/styles/admin.css';

/**
 * AdminSigningHistoryTab Component
 * 
 * Signing history management:
 * - List all signing records
 * - Filter by status, user
 * - View signature details
 * - Revoke signatures (admin action)
 */
export default function AdminSigningHistoryTab({ showMessage }) {
  const [signatures, setSignatures] = useState([]);
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
  const [selectedSignature, setSelectedSignature] = useState(null);

  useEffect(() => {
    loadSignatures();
  }, [pagination.page, search, filterStatus]);

  const loadSignatures = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const params = {
        page: pagination.page,
        per_page: pagination.perPage,
        search,
        status: filterStatus
      };
      
      const data = await getAdminSigningHistory(params);
      setSignatures(data.history || []);
      setPagination(prev => ({
        ...prev,
        total: data.pagination?.total || 0,
        totalPages: data.pagination?.total_pages || 0
      }));
    } catch (err) {
      setError('Không thể tải lịch sử ký số: ' + (err.message || err));
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
      await adminRevokeSignature(selectedSignature.id, 'admin_revoked');
      showMessage('Thu hồi chữ ký thành công!', 'success');
      setShowRevokeConfirm(false);
      setSelectedSignature(null);
      loadSignatures();
    } catch (err) {
      showMessage('Lỗi thu hồi chữ ký: ' + (err.message || err), 'error');
    }
  };

  const formatFileSize = (bytes) => {
    if (!bytes) return '-';
    const kb = bytes / 1024;
    if (kb < 1024) return `${kb.toFixed(1)} KB`;
    return `${(kb / 1024).toFixed(2)} MB`;
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
              placeholder="Tìm kiếm tài liệu, người dùng..."
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
          <button className="btn-refresh" onClick={loadSignatures} disabled={loading}>
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
              <option value="valid">Hợp lệ</option>
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
          <button onClick={loadSignatures}>Thử lại</button>
        </div>
      )}

      {/* Table */}
      <div className="admin-table-container">
        <table className="admin-table">
          <thead>
            <tr>
              <th>Tài liệu</th>
              <th>Người ký</th>
              <th>Chứng chỉ</th>
              <th>Kích thước</th>
              <th>Thời gian ký</th>
              <th>Trạng thái</th>
              <th>Lý do ký</th>
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
            ) : signatures.length === 0 ? (
              <tr>
                <td colSpan="8" className="empty-cell">
                  <FileText size={32} />
                  <span>Không có lịch sử ký số nào</span>
                </td>
              </tr>
            ) : (
              signatures.map(sig => (
                <tr key={sig.id} className={sig.status === 'revoked' ? 'row-revoked' : ''}>
                  <td>
                    <div className="document-cell">
                      <FileText size={18} className="doc-icon" />
                      <span className="doc-name" title={sig.document_name}>
                        {sig.document_name?.length > 30 
                          ? sig.document_name.substring(0, 30) + '...' 
                          : sig.document_name || '-'}
                      </span>
                    </div>
                  </td>
                  <td>
                    <div className="user-cell compact">
                      <span className="user-name">{sig.user}</span>
                    </div>
                  </td>
                  <td>
                    <span className={`cert-badge ${sig.certificate_active ? 'active' : 'revoked'}`}>
                      {sig.certificate_cn || '-'}
                    </span>
                  </td>
                  <td>{formatFileSize(sig.document_size)}</td>
                  <td>
                    {sig.signed_at 
                      ? new Date(sig.signed_at).toLocaleString('vi-VN', {
                          day: '2-digit',
                          month: '2-digit',
                          year: 'numeric',
                          hour: '2-digit',
                          minute: '2-digit'
                        })
                      : '-'}
                  </td>
                  <td>
                    <span className={`status-badge ${sig.status}`}>
                      {sig.status === 'valid' ? (
                        <>
                          <CheckCircle size={14} />
                          Hợp lệ
                        </>
                      ) : (
                        <>
                          <XCircle size={14} />
                          Thu hồi
                        </>
                      )}
                    </span>
                  </td>
                  <td>
                    <span className="reason-text" title={sig.reason}>
                      {sig.reason?.length > 20 
                        ? sig.reason.substring(0, 20) + '...' 
                        : sig.reason || '-'}
                    </span>
                  </td>
                  <td>
                    <div className="action-buttons">
                      <button 
                        className="btn-action view" 
                        onClick={() => { setSelectedSignature(sig); setShowDetailModal(true); }}
                        title="Xem chi tiết"
                      >
                        <Eye size={16} />
                      </button>
                      {sig.status === 'valid' && (
                        <button 
                          className="btn-action revoke" 
                          onClick={() => { setSelectedSignature(sig); setShowRevokeConfirm(true); }}
                          title="Thu hồi chữ ký"
                        >
                          <Ban size={16} />
                        </button>
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
            Hiển thị {signatures.length} / {pagination.total} bản ghi
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
      {showDetailModal && selectedSignature && (
        <SignatureDetailModal
          signature={selectedSignature}
          onClose={() => { setShowDetailModal(false); setSelectedSignature(null); }}
          onRevoke={() => {
            setShowDetailModal(false);
            setShowRevokeConfirm(true);
          }}
        />
      )}

      {/* Revoke Confirmation */}
      {showRevokeConfirm && selectedSignature && (
        <ConfirmDialog
          title="Thu hồi chữ ký"
          message={`Bạn có chắc muốn thu hồi chữ ký trên tài liệu "${selectedSignature.document_name}"?`}
          confirmText="Thu hồi"
          confirmType="danger"
          onConfirm={handleRevoke}
          onCancel={() => { setShowRevokeConfirm(false); setSelectedSignature(null); }}
        />
      )}
    </div>
  );
}
