import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  Users,
  Shield,
  FileText,
  Award,
  BarChart3,
  Settings,
  RefreshCw,
  TrendingUp,
  AlertTriangle,
  CheckCircle,
  Clock
} from 'lucide-react';
import AdminUsersTab from './AdminUsersTab';
import AdminCertificatesTab from './AdminCertificatesTab';
import AdminSigningHistoryTab from './AdminSigningHistoryTab';
import { getAdminStats } from '../../api';
import '../../static/styles/admin.css';

/**
 * AdminDashboard Component
 * 
 * Main admin panel with tabs for managing:
 * - Dashboard overview (stats)
 * - Users (CRUD)
 * - Certificates
 * - Signing History
 */
export default function AdminDashboard({ showMessage }) {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState('overview');
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadStats();
  }, []);

  const loadStats = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await getAdminStats();
      setStats(data);
    } catch (err) {
      setError('Không thể tải thống kê: ' + (err.message || err));
    } finally {
      setLoading(false);
    }
  };

  const tabs = [
    { id: 'overview', label: 'Tổng quan', icon: BarChart3 },
    { id: 'users', label: 'Người dùng', icon: Users },
    { id: 'certificates', label: 'Chứng chỉ', icon: Award },
    { id: 'signing-history', label: 'Lịch sử ký số', icon: FileText },
  ];

  const renderTabContent = () => {
    switch (activeTab) {
      case 'overview':
        return renderOverview();
      case 'users':
        return <AdminUsersTab showMessage={showMessage} />;
      case 'certificates':
        return <AdminCertificatesTab showMessage={showMessage} />;
      case 'signing-history':
        return <AdminSigningHistoryTab showMessage={showMessage} />;
      default:
        return renderOverview();
    }
  };

  const renderOverview = () => {
    if (loading) {
      return (
        <div className="admin-loading">
          <RefreshCw size={32} className="spinning" />
          <p>Đang tải thống kê...</p>
        </div>
      );
    }

    if (error) {
      return (
        <div className="admin-error">
          <AlertTriangle size={32} />
          <p>{error}</p>
          <button onClick={loadStats} className="btn-retry">Thử lại</button>
        </div>
      );
    }

    return (
      <div className="admin-overview">
        {/* Stats Cards */}
        <div className="stats-grid">
          <div className="stat-card users">
            <div className="stat-icon">
              <Users size={24} />
            </div>
            <div className="stat-content">
              <span className="stat-value">{stats?.users?.total || 0}</span>
              <span className="stat-label">Tổng người dùng</span>
            </div>
            <div className="stat-detail">
              <span className="detail-item success">
                <CheckCircle size={14} />
                {stats?.users?.active || 0} hoạt động
              </span>
              <span className="detail-item info">
                <Shield size={14} />
                {stats?.users?.admins || 0} admin
              </span>
            </div>
          </div>

          <div className="stat-card certificates">
            <div className="stat-icon">
              <Award size={24} />
            </div>
            <div className="stat-content">
              <span className="stat-value">{stats?.certificates?.total || 0}</span>
              <span className="stat-label">Tổng chứng chỉ</span>
            </div>
            <div className="stat-detail">
              <span className="detail-item success">
                <CheckCircle size={14} />
                {stats?.certificates?.active || 0} hợp lệ
              </span>
              <span className="detail-item warning">
                <Clock size={14} />
                {stats?.certificates?.expiring_soon || 0} sắp hết hạn
              </span>
            </div>
          </div>

          <div className="stat-card signatures">
            <div className="stat-icon">
              <FileText size={24} />
            </div>
            <div className="stat-content">
              <span className="stat-value">{stats?.signatures?.total || 0}</span>
              <span className="stat-label">Tổng chữ ký</span>
            </div>
            <div className="stat-detail">
              <span className="detail-item success">
                <CheckCircle size={14} />
                {stats?.signatures?.valid || 0} hợp lệ
              </span>
              <span className="detail-item info">
                <TrendingUp size={14} />
                {stats?.signatures?.this_month || 0} tháng này
              </span>
            </div>
          </div>

          <div className="stat-card activity">
            <div className="stat-icon">
              <TrendingUp size={24} />
            </div>
            <div className="stat-content">
              <span className="stat-value">{stats?.users?.new_this_month || 0}</span>
              <span className="stat-label">Người dùng mới</span>
            </div>
            <div className="stat-detail">
              <span className="detail-item info">
                Trong tháng này
              </span>
            </div>
          </div>
        </div>

        {/* Recent Activity */}
        <div className="recent-activity-section">
          <div className="recent-card">
            <h3>
              <Users size={18} />
              Người dùng mới đăng ký
            </h3>
            <div className="recent-list">
              {stats?.recent_users?.length > 0 ? (
                stats.recent_users.map((u, idx) => (
                  <div key={idx} className="recent-item">
                    <span className="recent-name">{u.username}</span>
                    <span className="recent-date">
                      {new Date(u.date_joined).toLocaleDateString('vi-VN')}
                    </span>
                    <span className={`status-badge ${u.is_active ? 'active' : 'inactive'}`}>
                      {u.is_active ? 'Hoạt động' : 'Khóa'}
                    </span>
                  </div>
                ))
              ) : (
                <p className="no-data">Chưa có dữ liệu</p>
              )}
            </div>
          </div>

          <div className="recent-card">
            <h3>
              <FileText size={18} />
              Ký số gần đây
            </h3>
            <div className="recent-list">
              {stats?.recent_signatures?.length > 0 ? (
                stats.recent_signatures.map((s, idx) => (
                  <div key={idx} className="recent-item">
                    <span className="recent-name">{s.document_name}</span>
                    <span className="recent-user">{s.username}</span>
                    <span className={`status-badge ${s.status}`}>
                      {s.status === 'valid' ? 'Hợp lệ' : s.status === 'revoked' ? 'Thu hồi' : s.status}
                    </span>
                  </div>
                ))
              ) : (
                <p className="no-data">Chưa có dữ liệu</p>
              )}
            </div>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="quick-actions">
          <h3>Thao tác nhanh</h3>
          <div className="action-buttons">
            <button onClick={() => setActiveTab('users')} className="action-btn">
              <Users size={20} />
              Quản lý người dùng
            </button>
            <button onClick={() => setActiveTab('certificates')} className="action-btn">
              <Award size={20} />
              Quản lý chứng chỉ
            </button>
            <button onClick={() => setActiveTab('signing-history')} className="action-btn">
              <FileText size={20} />
              Xem lịch sử ký số
            </button>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="admin-dashboard">
      {/* Header */}
      <div className="admin-header">
        <button className="back-button" onClick={() => navigate(-1)}>
          <ArrowLeft size={20} />
          Quay lại
        </button>
        <div className="admin-title">
          <Settings size={28} />
          <div>
            <h1>Bảng điều khiển Admin</h1>
            <p>Quản lý hệ thống CA</p>
          </div>
        </div>
        <button className="btn-refresh" onClick={loadStats} disabled={loading}>
          <RefreshCw size={18} className={loading ? 'spinning' : ''} />
          Làm mới
        </button>
      </div>

      {/* Tabs */}
      <div className="admin-tabs">
        {tabs.map(tab => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              className={`admin-tab ${activeTab === tab.id ? 'active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
            >
              <Icon size={18} />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Content */}
      <div className="admin-content">
        {renderTabContent()}
      </div>
    </div>
  );
}
