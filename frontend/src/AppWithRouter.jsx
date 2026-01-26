import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import { 
  register, 
  login, 
  logout, 
  getCurrentUser, 
  signPdf,
  getUserDashboardData 
} from './api';
import Header from './components/Header';
import AuthForm from './components/AuthForm';
import SignPDF from './components/SignPDF';
import PDFVerifier from './components/PDFVerifier';
import UserProfile from './components/UserProfile';
import SigningHistory from './components/SigningHistory';
import SigningHistoryDetail from './components/SigningHistoryDetail';
import CertificateManager from './components/CertificateManager';
import ChangePassword from './components/ChangePassword';
import AdminDashboard from './components/AdminDashboard';
import './static/styles/variables.css';
import './static/styles/global.css';
import './static/styles/components.css';
import './static/styles/signing-history.css';
import './static/styles/certificate-manager.css';
import './static/styles/admin.css';

/**
 * Main Application Component with Client-Side Routing
 * 
 * AUTHENTICATION:
 * - Uses Django session cookies (HttpOnly, persists across reloads)
 * - On mount: checks /api/usermanage/me/ to restore session
 * - User state stored in React state (username only, no password)
 * 
 * NAVIGATION:
 * - React Router for SPA navigation (no page reloads)
 * - Routes: /sign, /verify, /profile
 * - Session preserved across all routes
 */
function AppContent() {
  const [msg, setMsg] = useState('');
  const [msgType, setMsgType] = useState('');
  const [user, setUser] = useState(null); // {username, is_staff, is_active}
  const [loading, setLoading] = useState(true);
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [certificateInfo, setCertificateInfo] = useState(null);
  const [signingStats, setSigningStats] = useState(null);
  const navigate = useNavigate();

  /**
   * On component mount: restore session from server
   * This ensures user stays logged in after page reload
   */
  useEffect(() => {
    const restoreSession = async () => {
      try {
        const data = await getCurrentUser();
        if (data.authenticated) {
          setUser({
            username: data.username,
            is_staff: data.is_staff,
            is_active: data.is_active
          });
        }
      } catch (err) {
        console.error('Failed to restore session:', err);
      } finally {
        setLoading(false);
      }
    };
    
    restoreSession();
  }, []);

  /**
   * Fetch dashboard data when user is logged in
   */
  useEffect(() => {
    const fetchDashboardData = async () => {
      if (!user) {
        setCertificateInfo(null);
        setSigningStats(null);
        return;
      }
      
      try {
        const data = await getUserDashboardData();
        setCertificateInfo(data.certificate || null);
        setSigningStats(data.signing_stats || null);
      } catch (err) {
        console.error('Failed to fetch dashboard data:', err);
        // Set mock data for development if API not ready
        setCertificateInfo({
          status: 'valid',
          days_remaining: 365,
          common_name: user.username
        });
        setSigningStats({
          total_signed: 0,
          valid_signatures: 0,
          this_month: 0
        });
      }
    };
    
    fetchDashboardData();
  }, [user]);

  const showMessage = (message, type = 'success') => {
    setMsg(message);
    setMsgType(type);
    setTimeout(() => {
      setMsg('');
      setMsgType('');
    }, 5000);
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    const username = e.target.username.value;
    const password = e.target.password.value;
    
    // Collect profile data from enhanced registration form
    const profileData = {
      full_name: e.target.full_name?.value || '',
      email: e.target.email?.value || '',
      phone: e.target.phone?.value || '',
      department: e.target.department?.value || '',
      role: e.target.role?.value || 'student'
    };
    
    try {
      await register(username, password, profileData);
      showMessage(`Đăng ký thành công! Tài khoản ${username} đã được tạo và cấp chứng thư số PKI.`, 'success');
      setShowAuthModal(false);
    } catch (err) {
      showMessage(`Lỗi đăng ký: ${err.message || err}`, 'error');
      throw err; // Re-throw so AuthForm can handle it
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    const username = e.target.username.value;
    const password = e.target.password.value;
    try {
      const data = await login(username, password);
      // Session cookie is set by server (HttpOnly)
      // Store only username in React state (no password!)
      setUser({
        username: data.username,
        is_staff: data.is_staff || false,
        is_active: data.is_active !== false
      });
      setShowAuthModal(false);
      showMessage(`Đăng nhập thành công: ${username}`, 'success');
    } catch (err) {
      showMessage(`Lỗi đăng nhập: ${err.message || err}`, 'error');
    }
  };

  const handleLogout = async () => {
    try {
      await logout();
      setUser(null);
      setCertificateInfo(null);
      setSigningStats(null);
      navigate('/sign');
      showMessage('Đăng xuất thành công', 'success');
    } catch (err) {
      showMessage(`Lỗi đăng xuất: ${err.message || err}`, 'error');
    }
  };

  const handleSign = async (e) => {
    e.preventDefault();
    const file = e.target.file.files[0];
    if (!file) {
      showMessage('Vui lòng chọn file PDF', 'error');
      return;
    }
    
    if (!user) {
      showMessage('Vui lòng đăng nhập trước', 'error');
      setShowAuthModal(true);
      return;
    }
    
    const reason = e.target.reason?.value || 'Ký số tài liệu';
    const location = e.target.location?.value || 'Việt Nam';
    const position = e.target.position?.value || '';
    const signer_name = e.target.signer_name?.value || '';
    const title = e.target.title?.value || '';
    const custom_text = e.target.custom_text?.value || '';
    
    try {
      // Note: We need to get password somehow for signing
      // For now, keep the password prompt in SignPDF component
      // TODO: Backend should use session-based signing
      const password = e.target.password?.value;
      if (!password) {
        showMessage('Vui lòng nhập mật khẩu', 'error');
        return;
      }
      
      const blob = await signPdf(file, { username: user.username, password }, { 
        reason, 
        location, 
        position,
        signer_name,
        title,
        custom_text
      });
      
      if (e.__signedCallback) {
        e.__signedCallback(blob);
      }
      
      showMessage('Ký số thành công!', 'success');
    } catch (err) {
      showMessage(`Lỗi ký số: ${err.message || err}`, 'error');
    }
  };

  if (loading) {
    return (
      <div className="app-container">
        <div className="main-content" style={{display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh'}}>
          <p>Đang tải...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="app-container">
      <Header 
        user={user} 
        onAuthClick={() => setShowAuthModal(true)}
        onLogout={handleLogout}
        certificateInfo={certificateInfo}
        signingStats={signingStats}
      />
      
      <main className="main-content">
        <Routes>
          <Route path="/" element={<Navigate to="/sign" replace />} />
          <Route 
            path="/sign" 
            element={<SignPDF onSign={handleSign} username={user?.username} />} 
          />
          <Route 
            path="/verify" 
            element={<PDFVerifier />} 
          />
          <Route 
            path="/profile" 
            element={
              user ? (
                <UserProfile 
                  username={user.username} 
                  onBack={() => navigate('/sign')} 
                  showMessage={showMessage}
                  isAdmin={user.is_staff}
                />
              ) : (
                <Navigate to="/sign" replace />
              )
            } 
          />
          <Route 
            path="/signing-history" 
            element={
              user ? (
                <SigningHistory showMessage={showMessage} />
              ) : (
                <Navigate to="/sign" replace />
              )
            } 
          />
          <Route 
            path="/signing-history/:documentId" 
            element={
              user ? (
                <SigningHistoryDetail showMessage={showMessage} />
              ) : (
                <Navigate to="/sign" replace />
              )
            } 
          />
          <Route 
            path="/certificates" 
            element={
              user ? (
                <CertificateManager showMessage={showMessage} />
              ) : (
                <Navigate to="/sign" replace />
              )
            } 
          />
          <Route 
            path="/download-cert" 
            element={
              user ? (
                <Navigate to="/certificates" replace />
              ) : (
                <Navigate to="/sign" replace />
              )
            } 
          />
          <Route 
            path="/change-password" 
            element={
              user ? (
                <ChangePassword 
                  showMessage={showMessage}
                  onBack={() => navigate(-1)}
                />
              ) : (
                <Navigate to="/sign" replace />
              )
            } 
          />
          {/* Admin routes */}
          <Route 
            path="/admin" 
            element={
              user?.is_staff ? (
                <AdminDashboard showMessage={showMessage} />
              ) : (
                <Navigate to="/sign" replace />
              )
            } 
          />
          <Route 
            path="/admin/*" 
            element={
              user?.is_staff ? (
                <AdminDashboard showMessage={showMessage} />
              ) : (
                <Navigate to="/sign" replace />
              )
            } 
          />
        </Routes>
        
        {msg && (
          <div className={`message ${msgType}`}>
            {msg}
          </div>
        )}
      </main>

      {showAuthModal && (
        <div className="modal-overlay" onClick={() => setShowAuthModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <AuthForm 
              onRegister={handleRegister} 
              onLogin={handleLogin}
              onClose={() => setShowAuthModal(false)}
            />
          </div>
        </div>
      )}
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AppContent />
    </BrowserRouter>
  );
}
