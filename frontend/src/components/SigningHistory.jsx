import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  FileText,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Clock,
  Search,
  Filter,
  Download,
  RefreshCw,
  Calendar,
  Shield
} from 'lucide-react';
import { getSigningHistory } from '../api';
import '../static/styles/signing-history.css';

/**
 * SigningHistory Component
 * 
 * Displays a list of documents signed by the user with:
 * - Document name
 * - Signing time
 * - Certificate used
 * - Signature status
 * 
 * Features:
 * - Search/filter
 * - Status filtering
 * - Pagination
 * - Export capability
 */
export default function SigningHistory({ username }) {
  const navigate = useNavigate();
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 10;

  useEffect(() => {
    loadHistory();
  }, [username]);

  const loadHistory = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await getSigningHistory();
      setHistory(data.history || []);
    } catch (err) {
      setError('Không thể tải lịch sử ký số: ' + (err.message || err));
    } finally {
      setLoading(false);
    }
  };

  // Filter and search
  const filteredHistory = history.filter(item => {
    const matchesSearch = item.document_name.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = statusFilter === 'all' || item.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  // Pagination
  const totalPages = Math.ceil(filteredHistory.length / itemsPerPage);
  const paginatedHistory = filteredHistory.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  );

  // Status badge component
  const StatusBadge = ({ status }) => {
    const config = {
      valid: { icon: CheckCircle, text: 'Hợp lệ', className: 'status-valid' },
      revoked: { icon: XCircle, text: 'Đã thu hồi', className: 'status-revoked' },
      expired: { icon: AlertTriangle, text: 'Hết hạn', className: 'status-expired' },
      invalid: { icon: XCircle, text: 'Không hợp lệ', className: 'status-invalid' }
    };

    const { icon: Icon, text, className } = config[status] || config.invalid;

    return (
      <span className={`status-badge ${className}`}>
        <Icon size={14} />
        {text}
      </span>
    );
  };

  // Format date
  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleString('vi-VN', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  // Format file size
  const formatSize = (bytes) => {
    if (!bytes) return '-';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  };

  return (
    <div className="signing-history-container">
      {/* Header */}
      <div className="history-header">
        <button className="back-button" onClick={() => navigate(-1)}>
          <ArrowLeft size={20} />
          Quay lại
        </button>
        <h1 className="history-title">
          <FileText size={24} />
          Lịch sử ký số
        </h1>
      </div>

      {/* Controls */}
      <div className="history-controls">
        <div className="search-box">
          <Search size={18} />
          <input
            type="text"
            placeholder="Tìm kiếm theo tên tài liệu..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>

        <div className="filter-group">
          <Filter size={18} />
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="all">Tất cả trạng thái</option>
            <option value="valid">Hợp lệ</option>
            <option value="revoked">Đã thu hồi</option>
            <option value="expired">Hết hạn</option>
          </select>
        </div>

        <button className="refresh-button" onClick={loadHistory} disabled={loading}>
          <RefreshCw size={18} className={loading ? 'spinning' : ''} />
          Làm mới
        </button>
      </div>

      {/* Stats Summary */}
      <div className="history-stats">
        <div className="stat-card">
          <span className="stat-number">{history.length}</span>
          <span className="stat-label">Tổng số</span>
        </div>
        <div className="stat-card valid">
          <span className="stat-number">{history.filter(h => h.status === 'valid').length}</span>
          <span className="stat-label">Hợp lệ</span>
        </div>
        <div className="stat-card warning">
          <span className="stat-number">{history.filter(h => h.status === 'revoked').length}</span>
          <span className="stat-label">Thu hồi</span>
        </div>
        <div className="stat-card expired">
          <span className="stat-number">{history.filter(h => h.status === 'expired').length}</span>
          <span className="stat-label">Hết hạn</span>
        </div>
      </div>

      {/* Content */}
      {loading ? (
        <div className="loading-state">
          <RefreshCw size={32} className="spinning" />
          <p>Đang tải lịch sử ký số...</p>
        </div>
      ) : error ? (
        <div className="error-state">
          <AlertTriangle size={32} />
          <p>{error}</p>
          <button onClick={loadHistory}>Thử lại</button>
        </div>
      ) : filteredHistory.length === 0 ? (
        <div className="empty-state">
          <FileText size={48} />
          <h3>Chưa có lịch sử ký số</h3>
          <p>Bạn chưa ký số tài liệu nào hoặc không có kết quả phù hợp với bộ lọc.</p>
        </div>
      ) : (
        <>
          {/* Table */}
          <div className="history-table-container">
            <table className="history-table">
              <thead>
                <tr>
                  <th>Tài liệu</th>
                  <th>Thời gian ký</th>
                  <th>Chứng chỉ</th>
                  <th>Kích thước</th>
                  <th>Trạng thái</th>
                  <th>Hành động</th>
                </tr>
              </thead>
              <tbody>
                {paginatedHistory.map((item, index) => (
                  <tr key={item.id || index}>
                    <td className="doc-name">
                      <FileText size={16} />
                      <span title={item.document_name}>
                        {item.document_name.length > 40 
                          ? item.document_name.substring(0, 40) + '...' 
                          : item.document_name}
                      </span>
                    </td>
                    <td className="sign-time">
                      <Calendar size={14} />
                      {formatDate(item.signed_at)}
                    </td>
                    <td className="cert-info">
                      <Shield size={14} />
                      {item.certificate_cn || 'N/A'}
                    </td>
                    <td className="doc-size">
                      {formatSize(item.document_size)}
                    </td>
                    <td>
                      <StatusBadge status={item.status} />
                    </td>
                    <td className="actions">
                      {item.document_hash && (
                        <button 
                          className="action-btn"
                          title="Xem chi tiết"
                          onClick={() => navigate(`/signing-history/${item.id}`)}
                        >
                          <Search size={14} />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="pagination">
              <button 
                disabled={currentPage === 1}
                onClick={() => setCurrentPage(p => p - 1)}
              >
                Trước
              </button>
              <span>Trang {currentPage} / {totalPages}</span>
              <button 
                disabled={currentPage === totalPages}
                onClick={() => setCurrentPage(p => p + 1)}
              >
                Sau
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
