import React, { useState, useRef } from 'react';
import { Upload, CheckCircle, XCircle, AlertCircle, AlertTriangle, Shield, Clock, User, FileText, FileCheck } from 'lucide-react';
import '../static/styles/verify.css';

export default function PDFVerifier() {
  const [file, setFile] = useState(null);
  const [verifying, setVerifying] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef(null);

  const handleFileSelect = (e) => {
    const selected = e.target.files[0];
    if (selected && selected.type === 'application/pdf') {
      setFile(selected);
      setResult(null);
      setError(null);
    } else {
      setError('Vui lòng chọn file PDF');
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile && droppedFile.type === 'application/pdf') {
      setFile(droppedFile);
      setResult(null);
      setError(null);
    } else {
      setError('Vui lòng chọn file PDF');
    }
  };

  const verifyPDF = async () => {
    if (!file) return;

    setVerifying(true);
    setError(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('/api/sign/verify/', {
        method: 'POST',
        body: formData,
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error('Xác thực thất bại');
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(err.message || 'Không thể xác thực PDF');
    } finally {
      setVerifying(false);
    }
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return 'N/A';
    const date = new Date(dateStr);
    return date.toLocaleString('vi-VN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  return (
    <div className="verify-card">
      <div className="card-header">
        <FileCheck size={24} color="#075794" />
        <h2>Xác thực chữ ký PDF</h2>
      </div>

      <div
        className={`upload-zone ${isDragging ? 'dragging' : ''} ${file ? 'has-file' : ''}`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept="application/pdf"
          onChange={handleFileSelect}
          style={{ display: 'none' }}
        />
        
        {file ? (
          <div className="file-selected">
            <FileText size={48} color="#075794" />
            <div className="file-info">
              <p className="file-name">{file.name}</p>
              <p className="file-size">
                {(file.size / 1024).toFixed(2)} KB
              </p>
            </div>
          </div>
        ) : (
          <div className="upload-prompt">
            <Upload size={48} color="#9CA3AF" />
            <p className="upload-text">
              Kéo thả file PDF vào đây hoặc <span className="upload-link">chọn file</span>
            </p>
            <p className="upload-hint">Chỉ chấp nhận file PDF</p>
          </div>
        )}
      </div>

      {file && (
        <button 
          onClick={verifyPDF} 
          disabled={verifying} 
          className="btn btn-primary btn-block"
        >
          <Shield size={18} />
          {verifying ? 'Đang xác thực...' : 'Xác thực chữ ký'}
        </button>
      )}

      {error && (
        <div className="alert alert-error">
          <XCircle size={20} />
          <div>
            <div className="alert-title">Xác thực thất bại</div>
            <div className="alert-message">{error}</div>
          </div>
        </div>
      )}

      {result && (
        <div className="verify-result">
          <div className={`result-status ${result.valid ? 'valid' : 'invalid'}`}>
            {result.valid ? (
              <CheckCircle size={28} />
            ) : (
              <XCircle size={28} />
            )}
            <div>
              <div className="status-title">
                {result.valid ? 'Chữ ký hợp lệ' : 'Chữ ký không hợp lệ'}
              </div>
              <div className="status-subtitle">
                Tìm thấy {result.signature_count} chữ ký
              </div>
            </div>
          </div>

          {result.signatures && result.signatures.map((sig, idx) => (
            <div key={idx} className="signature-card">
              <div className="signature-header">
                <div className="signature-title">
                  <User size={20} />
                  <span>Chữ ký #{idx + 1}</span>
                </div>
                <div className={`signature-badge ${sig.valid ? 'valid' : 'invalid'}`}>
                  {sig.valid ? 'Hợp lệ' : 'Không hợp lệ'}
                </div>
              </div>

              <div className="signature-grid">
                <div className="signature-detail">
                  <div className="detail-label">Người ký</div>
                  <div className="detail-value">{sig.signer}</div>
                </div>

                {sig.timestamp && (
                  <div className="signature-detail">
                    <div className="detail-label">
                      <Clock size={14} />
                      Thời gian ký
                    </div>
                    <div className="detail-value">{formatDate(sig.timestamp)}</div>
                  </div>
                )}

                <div className="signature-detail">
                  <div className="detail-label">Trạng thái tin cậy</div>
                  <div className="detail-value status">
                    {sig.trust_status === 'TRUSTED' ? (
                      <CheckCircle size={16} color="#16a34a" />
                    ) : (
                      <AlertCircle size={16} color="#d97706" />
                    )}
                    <span>{sig.trust_status}</span>
                  </div>
                </div>

                <div className="signature-detail">
                  <div className="detail-label">Tính toàn vẹn chữ ký</div>
                  <div className="detail-value status">
                    {sig.signature_intact ? (
                      <CheckCircle size={16} color="#16a34a" />
                    ) : (
                      <XCircle size={16} color="#dc2626" />
                    )}
                    <span>{sig.signature_intact ? 'Hợp lệ' : 'Không hợp lệ'}</span>
                  </div>
                </div>
                
                <div className="signature-detail">
                  <div className="detail-label">Tài liệu sau khi ký</div>
                  <div className="detail-value status">
                    {sig.document_intact ? (
                      <CheckCircle size={16} color="#16a34a" />
                    ) : (
                      <AlertTriangle size={16} color="#f59e0b" />
                    )}
                    <span>{sig.document_intact ? 'Không thay đổi' : 'Có thay đổi'}</span>
                  </div>
                </div>
              </div>

              {sig.certificate_info && (
                <div className="certificate-info">
                  <div className="cert-title">Chi tiết chứng chỉ</div>
                  
                  <div className="cert-detail">
                    <div className="detail-label">Subject</div>
                    <div className="detail-value mono">{sig.certificate_info.subject}</div>
                  </div>
                  
                  <div className="cert-detail">
                    <div className="detail-label">Issuer</div>
                    <div className="detail-value mono">{sig.certificate_info.issuer}</div>
                  </div>
                  
                  <div className="cert-dates">
                    <div className="cert-detail">
                      <div className="detail-label">Hiệu lực từ</div>
                      <div className="detail-value">{formatDate(sig.certificate_info.valid_from)}</div>
                    </div>
                    <div className="cert-detail">
                      <div className="detail-label">Hiệu lực đến</div>
                      <div className="detail-value">{formatDate(sig.certificate_info.valid_to)}</div>
                    </div>
                  </div>
                  
                  <div className="cert-detail">
                    <div className="detail-label">Serial Number</div>
                    <div className="detail-value mono">{sig.certificate_info.serial_number}</div>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
