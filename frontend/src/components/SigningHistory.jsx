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
  Shield,
  Trash2,
  Eye
} from 'lucide-react';
import { getSignedDocuments, downloadSignedDocument, getSigningHistoryStats } from '../api';
import '../static/styles/signing-history.css';

/**
 * SigningHistory Component
 * 
 * Displays a list of documents signed by the user with:
 * - Document name
 * - Signing time
 * - Certificate used
 * - Signature status
 * - Download capability (for non-expired documents)
 * 
 * Features:
 * - Search/filter
 * - Status filtering
 * - Pagination
 * - Download signed PDFs
 * - Expiration indicators
 */
export default function SigningHistory({ username }) {
  const navigate = useNavigate();
  const [documents, setDocuments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [downloadableOnly, setDownloadableOnly] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [pagination, setPagination] = useState({ total: 0, total_pages: 1 });
  const [stats, setStats] = useState(null);
  const [downloading, setDownloading] = useState(null); // Track which document is downloading
  const itemsPerPage = 20;

  useEffect(() => {
    loadDocuments();
    loadStats();
  }, [currentPage, statusFilter, downloadableOnly]);

  // Debounced search
  useEffect(() => {
    const timer = setTimeout(() => {
      if (currentPage === 1) {
        loadDocuments();
      } else {
        setCurrentPage(1);
      }
    }, 300);
    return () => clearTimeout(timer);
  }, [searchTerm]);

  const loadDocuments = async () => {
    try {
      setLoading(true);
      setError(null);
      const filters = {
        status: statusFilter !== 'all' ? statusFilter : undefined,
        search: searchTerm || undefined,
        downloadable_only: downloadableOnly || undefined
      };
      const data = await getSignedDocuments(currentPage, itemsPerPage, filters);
      setDocuments(data.documents || []);
      // API returns: total, page, limit, has_more
      const totalPages = Math.ceil((data.total || 0) / itemsPerPage);
      setPagination({ 
        total: data.total || 0, 
        total_pages: totalPages || 1 
      });
    } catch (err) {
      setError('Không thể tải lịch sử ký số: ' + (err.message || err));
      setDocuments([]);
    } finally {
      setLoading(false);
    }
  };

  const loadStats = async () => {
    try {
      const data = await getSigningHistoryStats();
      setStats(data);
    } catch (err) {
      console.error('Failed to load stats:', err);
    }
  };

  const handleDownload = async (doc) => {
    if (!doc.is_downloadable) {
      alert('Tài liệu này không còn khả dụng để tải xuống');
      return;
    }

    try {
      setDownloading(doc.id);
      const blob = await downloadSignedDocument(doc.id);
      
      // Create download link
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = doc.document_name.replace('.pdf', '_signed.pdf');
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);

      // Refresh to update download count
      loadDocuments();
    } catch (err) {
      alert('Lỗi tải xuống: ' + (err.message || err));
    } finally {
      setDownloading(null);
    }
  };

  // Status badge component
  const StatusBadge = ({ status }) => {
    const config = {
      valid: { icon: CheckCircle, text: 'Hợp lệ', className: 'status-valid' },
      revoked: { icon: XCircle, text: 'Đã thu hồi', className: 'status-revoked' },
      expired: { icon: AlertTriangle, text: 'Hết hạn', className: 'status-expired' },
      deleted: { icon: Trash2, text: 'Đã xóa', className: 'status-deleted' },
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

  // Downloadable badge
  const DownloadableBadge = ({ doc }) => {
    if (!doc.file_path) {
      return <span className="download-badge unavailable">Không lưu</span>;
    }
    if (!doc.is_downloadable) {
      return <span className="download-badge expired">Hết hạn tải</span>;
    }
    
    const expiresAt = new Date(doc.expires_at);
    const now = new Date();
    const daysLeft = Math.ceil((expiresAt - now) / (1000 * 60 * 60 * 24));
    
    if (daysLeft <= 3) {
      return <span className="download-badge warning">Còn {daysLeft} ngày</span>;
    }
    return <span className="download-badge available">Có thể tải</span>;
  };

  // Format date
  const formatDate = (dateString) => {
    if (!dateString) return '-';
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
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setCurrentPage(1);
            }}
          >
            <option value="all">Tất cả trạng thái</option>
            <option value="valid">Hợp lệ</option>
            <option value="revoked">Đã thu hồi</option>
            <option value="expired">Hết hạn</option>
          </select>
        </div>

        <label className="filter-checkbox">
          <input
            type="checkbox"
            checked={downloadableOnly}
            onChange={(e) => {
              setDownloadableOnly(e.target.checked);
              setCurrentPage(1);
            }}
          />
          <Download size={16} />
          Chỉ hiện có thể tải
        </label>

        <button className="refresh-button" onClick={loadDocuments} disabled={loading}>
          <RefreshCw size={18} className={loading ? 'spinning' : ''} />
          Làm mới
        </button>
      </div>

      {/* Stats Summary */}
      <div className="history-stats">
        <div className="stat-card">
          <span className="stat-number">{stats?.total_signed ?? documents.length}</span>
          <span className="stat-label">Tổng số</span>
        </div>
        <div className="stat-card valid">
          <span className="stat-number">{stats?.valid_signatures ?? 0}</span>
          <span className="stat-label">Hợp lệ</span>
        </div>
        <div className="stat-card warning">
          <span className="stat-number">{stats?.downloadable_documents ?? 0}</span>
          <span className="stat-label">Có thể tải</span>
        </div>
        <div className="stat-card info">
          <span className="stat-number">{stats?.total_download_count ?? 0}</span>
          <span className="stat-label">Lượt tải</span>
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
          <button onClick={loadDocuments}>Thử lại</button>
        </div>
      ) : documents.length === 0 ? (
        <div className="empty-state">
          <FileText size={48} />
          <h3>Chưa có lịch sử ký số</h3>
          <p>Bạn chưa ký số tài liệu nào hoặc không có kết quả phù hợp với bộ lọc.</p>
          <button className="primary-button" onClick={() => navigate('/sign')}>
            Ký tài liệu mới
          </button>
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
                  <th>Tải xuống</th>
                  <th>Hành động</th>
                </tr>
              </thead>
              <tbody>
                {documents.map((doc) => (
                  <tr key={doc.id}>
                    <td className="doc-name">
                      <FileText size={16} />
                      <span title={doc.document_name}>
                        {doc.document_name.length > 35 
                          ? doc.document_name.substring(0, 35) + '...' 
                          : doc.document_name}
                      </span>
                    </td>
                    <td className="sign-time">
                      <Calendar size={14} />
                      {formatDate(doc.signed_at)}
                    </td>
                    <td className="cert-info">
                      <Shield size={14} />
                      {doc.certificate_cn || 'N/A'}
                    </td>
                    <td className="doc-size">
                      {formatSize(doc.document_size)}
                    </td>
                    <td>
                      <StatusBadge status={doc.status} />
                    </td>
                    <td>
                      <DownloadableBadge doc={doc} />
                      {doc.download_count > 0 && (
                        <span className="download-count" title="Số lần tải">
                          ({doc.download_count})
                        </span>
                      )}
                    </td>
                    <td className="actions">
                      {doc.is_downloadable && (
                        <button 
                          className="action-btn download-btn"
                          title="Tải xuống PDF đã ký"
                          onClick={() => handleDownload(doc)}
                          disabled={downloading === doc.id}
                        >
                          {downloading === doc.id ? (
                            <RefreshCw size={14} className="spinning" />
                          ) : (
                            <Download size={14} />
                          )}
                        </button>
                      )}
                      <button 
                        className="action-btn"
                        title="Xem chi tiết"
                        onClick={() => navigate(`/signing-history/${doc.id}`)}
                      >
                        <Eye size={14} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {pagination.total_pages > 1 && (
            <div className="pagination">
              <button 
                disabled={currentPage === 1}
                onClick={() => setCurrentPage(p => p - 1)}
              >
                Trước
              </button>
              <span>Trang {currentPage} / {pagination.total_pages}</span>
              <button 
                disabled={currentPage === pagination.total_pages}
                onClick={() => setCurrentPage(p => p + 1)}
              >
                Sau
              </button>
            </div>
          )}

          {/* Retention Notice */}
          <div className="retention-notice">
            <Clock size={16} />
            <span>
              Tài liệu đã ký được lưu trữ trong 14 ngày. Sau thời gian này, bạn sẽ không thể tải xuống.
            </span>
          </div>
        </>
      )}
    </div>
  );
}
