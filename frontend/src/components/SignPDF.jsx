import React, { useState, useRef } from 'react';
import { FileSignature, Upload, Download, AlertCircle, Settings, X } from 'lucide-react';
import PDFViewer from './PDFViewer';
import '../static/styles/sign.css';

export default function SignPDF({ onSign, username }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [signOptions, setSignOptions] = useState({
    reason: 'Ký số tài liệu'
  });
  const [previewUrl, setPreviewUrl] = useState(null);
  const [signedPdfUrl, setSignedPdfUrl] = useState(null);
  const [signatureArea, setSignatureArea] = useState(null);
  const fileInputRef = useRef(null);

  const handleFileSelect = (e) => {
    const file = e.target.files[0];
    if (file && file.type === 'application/pdf') {
      setSelectedFile(file);
      const url = URL.createObjectURL(file);
      setPreviewUrl(url);
      setSignedPdfUrl(null);
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
    
    const file = e.dataTransfer.files[0];
    if (file && file.type === 'application/pdf') {
      setSelectedFile(file);
      const url = URL.createObjectURL(file);
      setPreviewUrl(url);
      setSignedPdfUrl(null);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (selectedFile) {
      const positionValue = signatureArea ? `${signatureArea.page}/${signatureArea.x1},${signatureArea.y1},${signatureArea.x2},${signatureArea.y2}` : '';
      console.log('Submitting with position:', positionValue);
      console.log('Signature area:', signatureArea);
      console.log('Text config:', {
        signer_name: signOptions.signerName,
        title: signOptions.title,
        custom_text: signOptions.customText
      });
      
      const mockEvent = {
        preventDefault: () => {},
        target: {
          file: { files: [selectedFile] },
          password: { value: signOptions.password || '' }, // Added password field
          reason: { value: signOptions.reason },
          position: { value: positionValue },
          signer_name: { value: signOptions.signerName || '' },
          title: { value: signOptions.title || '' },
          custom_text: { value: signOptions.customText || '' }
        },
        __signedCallback: (blob) => {
          const url = URL.createObjectURL(blob);
          setSignedPdfUrl(url);
        }
      };
      await onSign(mockEvent);
    }
  };

  const handleSelectArea = (area) => {
    setSignatureArea(area);
  };

  const handleDownload = () => {
    if (!signedPdfUrl) return;
    const a = document.createElement('a');
    a.href = signedPdfUrl;
    a.download = `signed_${selectedFile.name}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  const handleReset = () => {
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    if (signedPdfUrl) URL.revokeObjectURL(signedPdfUrl);
    setSelectedFile(null);
    setPreviewUrl(null);
    setSignedPdfUrl(null);
    setSignatureArea(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  return (
    <div className="sign-card">
      <div className="card-header">
        <FileSignature size={24} color="#075794" />
        <h2>Ký số PDF</h2>
      </div>

      {!username ? (
        <div className="alert alert-warning">
          <AlertCircle size={20} />
          <span>Vui lòng đăng nhập để sử dụng chức năng ký số</span>
        </div>
      ) : (
        <form onSubmit={handleSubmit}>
          <div
            className={`upload-zone ${isDragging ? 'dragging' : ''} ${selectedFile ? 'has-file' : ''}`}
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
            
            {selectedFile ? (
              <div className="file-selected">
                <FileSignature size={48} color="#075794" />
                <div className="file-info">
                  <p className="file-name">{selectedFile.name}</p>
                  <p className="file-size">
                    {(selectedFile.size / 1024).toFixed(2)} KB
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

          {selectedFile && !signedPdfUrl && (
            <>
              {previewUrl && (
                <div className="pdf-preview">
                  <div className="preview-header">
                    <h3>Chọn vị trí ký trên PDF</h3>
                    <button type="button" className="btn-icon" onClick={handleReset}>
                      <X size={20} />
                    </button>
                  </div>
                  <PDFViewer 
                    pdfUrl={previewUrl}
                    onSelectArea={handleSelectArea}
                    showSelection={true}
                  />
                  {signatureArea && (
                    <div className="selection-info">
                      ✓ Đã chọn vị trí: Trang {signatureArea.page + 1}, 
                      Tọa độ ({Math.round(signatureArea.x1)}, {Math.round(signatureArea.y1)}, 
                      {Math.round(signatureArea.x2)}, {Math.round(signatureArea.y2)})
                    </div>
                  )}
                </div>
              )}

              <button
                type="button"
                className="btn btn-secondary btn-block"
                onClick={() => setShowAdvanced(!showAdvanced)}
              >
                <Settings size={18} />
                {showAdvanced ? 'Ẩn tùy chọn nâng cao' : 'Tùy chọn nâng cao'}
              </button>

              {showAdvanced && (
                <div className="advanced-options">
                  <div className="form-group">
                    <label htmlFor="password">Mật khẩu *</label>
                    <input
                      type="password"
                      id="password"
                      value={signOptions.password || ''}
                      onChange={(e) => setSignOptions({...signOptions, password: e.target.value})}
                      placeholder="Nhập mật khẩu để ký"
                      required
                    />
                    <small className="field-hint">Mật khẩu tài khoản của bạn</small>
                  </div>
                  
                  <div className="stamp-text-section">
                    <h4>📝 Tùy chỉnh nội dung hiển thị trong stamp</h4>
                    <p className="section-hint">Các trường dưới đây sẽ hiển thị trong chữ ký điện tử trên PDF</p>
                    
                    <div className="form-group">
                      <label htmlFor="signerName">Tên người ký (hiển thị trên stamp)</label>
                      <input
                        type="text"
                        id="signerName"
                        value={signOptions.signerName || ''}
                        onChange={(e) => setSignOptions({...signOptions, signerName: e.target.value})}
                        placeholder={`Mặc định: ${username}`}
                      />
                      <small className="field-hint">Để trống để dùng username hiện tại</small>
                    </div>

                    <div className="form-group">
                      <label htmlFor="title">Chức danh / Vai trò</label>
                      <input
                        type="text"
                        id="title"
                        value={signOptions.title || ''}
                        onChange={(e) => setSignOptions({...signOptions, title: e.target.value})}
                        placeholder="VD: Giám đốc, Trưởng phòng, Phó giám đốc..."
                      />
                      <small className="field-hint">Hiển thị dưới tên người ký</small>
                    </div>

                    <div className="form-group">
                      <label htmlFor="customText">Dòng chữ tùy chọn</label>
                      <input
                        type="text"
                        id="customText"
                        value={signOptions.customText || ''}
                        onChange={(e) => setSignOptions({...signOptions, customText: e.target.value})}
                        placeholder="VD: Đã phê duyệt, Đã xét duyệt, Đồng ý..."
                      />
                      <small className="field-hint">Hiển thị bên dưới (màu xanh, in nghiêng)</small>
                    </div>
                  </div>

                  <div className="form-group">
                    <label htmlFor="reason">Lý do ký</label>
                    <input
                      type="text"
                      id="reason"
                      value={signOptions.reason}
                      onChange={(e) => setSignOptions({...signOptions, reason: e.target.value})}
                      placeholder="Nhập lý do ký số"
                    />
                  </div>
                </div>
              )}

              {!signatureArea && (
                <div className="alert alert-warning">
                  <AlertCircle size={20} />
                  <span>Vui lòng kéo chuột trên PDF để chọn vị trí hiển thị chữ ký</span>
                </div>
              )}
              
              <button 
                type="submit" 
                className="btn btn-primary btn-block"
                disabled={!signatureArea}
              >
                <FileSignature size={18} />
                Ký PDF
              </button>
            </>
          )}

          {signedPdfUrl && (
            <>
              <div className="pdf-preview">
                <div className="preview-header">
                  <h3>PDF đã ký</h3>
                  <button type="button" className="btn-icon" onClick={handleReset}>
                    <X size={20} />
                  </button>
                </div>
                <PDFViewer 
                  pdfUrl={signedPdfUrl}
                  showSelection={false}
                />
              </div>
              <button 
                type="button" 
                className="btn btn-success btn-block"
                onClick={handleDownload}
              >
                <Download size={18} />
                Tải xuống PDF đã ký
              </button>
            </>
          )}
        </form>
      )}
    </div>
  );
}
