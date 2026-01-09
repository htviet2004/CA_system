import React, { useState } from 'react';
import { register, login, signPdf } from './api';
import Header from './components/Header';
import AuthForm from './components/AuthForm';
import SignPDF from './components/SignPDF';
import PDFVerifier from './components/PDFVerifier';
import UserProfile from './components/UserProfile';
import './static/styles/variables.css';
import './static/styles/global.css';
import './static/styles/components.css';

export default function App() {
  const [msg, setMsg] = useState('');
  const [msgType, setMsgType] = useState('');
  const [logged, setLogged] = useState({ username: '', password: '' });
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [activeTab, setActiveTab] = useState('sign');

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
    try {
      await register(username, password);
      showMessage(`Đăng ký thành công cho tài khoản: ${username}`, 'success');
    } catch (err) {
      showMessage(`Lỗi đăng ký: ${err.message || err}`, 'error');
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    const username = e.target.username.value;
    const password = e.target.password.value;
    try {
      await login(username, password);
      setLogged({ username, password });
      setShowAuthModal(false);
      showMessage(`Đăng nhập thành công: ${username}`, 'success');
    } catch (err) {
      showMessage(`Lỗi đăng nhập: ${err.message || err}`, 'error');
    }
  };

  const handleSign = async (e) => {
    e.preventDefault();
    const file = e.target.file.files[0];
    if (!file) {
      showMessage('Vui lòng chọn file PDF', 'error');
      return;
    }
    
    const reason = e.target.reason?.value || 'Ký số tài liệu';
    const location = e.target.location?.value || 'Việt Nam';
    const position = e.target.position?.value || '';
    
    try {
      const blob = await signPdf(file, logged, { reason, location, position });
      
      if (e.__signedCallback) {
        e.__signedCallback(blob);
      }
      
      showMessage('Ký số thành công!', 'success');
    } catch (err) {
      showMessage(`Lỗi ký số: ${err.message || err}`, 'error');
    }
  };

  return (
    <div className="app-container">
      <Header 
        username={logged.username} 
        activeTab={activeTab}
        onTabChange={setActiveTab}
        onAuthClick={() => setShowAuthModal(true)}
        onLogout={() => setLogged({ username: '', password: '' })}
        onEditProfile={() => setActiveTab('profile')} 
      />
      
      <main className="main-content">
        {activeTab === 'sign' && (
          <SignPDF onSign={handleSign} username={logged.username} />
        )}

        {activeTab === 'verify' && (
          <PDFVerifier />
        )}

        {activeTab === 'profile' && (
          <UserProfile username={logged.username} onBack={() => setActiveTab('sign')} showMessage={showMessage} />
        )}
        
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
