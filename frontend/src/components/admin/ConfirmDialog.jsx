import React from 'react';
import { AlertTriangle, CheckCircle, Info, HelpCircle } from 'lucide-react';
import '../../static/styles/admin.css';

/**
 * ConfirmDialog Component
 * 
 * Reusable confirmation dialog with customizable:
 * - Title
 * - Message
 * - Button text and type
 */
export default function ConfirmDialog({ 
  title, 
  message, 
  confirmText = 'Xác nhận',
  cancelText = 'Hủy',
  confirmType = 'primary', // primary, danger, warning
  onConfirm,
  onCancel
}) {
  const getIcon = () => {
    switch (confirmType) {
      case 'danger':
        return <AlertTriangle size={24} />;
      case 'warning':
        return <Info size={24} />;
      default:
        return <HelpCircle size={24} />;
    }
  };

  return (
    <div className="modal-overlay" onClick={onCancel}>
      <div className="modal-content confirm-dialog" onClick={e => e.stopPropagation()}>
        <div className={`dialog-header ${confirmType}`}>
          {getIcon()}
          <h3>{title}</h3>
        </div>
        <div className="dialog-body">
          <p>{message}</p>
        </div>
        <div className="dialog-footer">
          <button className="btn-cancel" onClick={onCancel}>
            {cancelText}
          </button>
          <button className={`btn-${confirmType}`} onClick={onConfirm}>
            {confirmText}
          </button>
        </div>
      </div>
    </div>
  );
}
