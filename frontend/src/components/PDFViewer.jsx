import React, { useRef, useEffect, useState } from 'react';
import * as pdfjsLib from 'pdfjs-dist';

// Configure PDF.js worker
pdfjsLib.GlobalWorkerOptions.workerSrc = `//cdnjs.cloudflare.com/ajax/libs/pdf.js/${pdfjsLib.version}/pdf.worker.min.js`;

export default function PDFViewer({ pdfUrl, onSelectArea, showSelection = true, selectedArea = null }) {
  const canvasRef = useRef(null);
  const overlayRef = useRef(null);
  const containerRef = useRef(null);
  const renderTaskRef = useRef(null);
  const pageRef = useRef(null);
  const viewportRef = useRef(null);
  const [pdfDoc, setPdfDoc] = useState(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [numPages, setNumPages] = useState(0);
  const [scale, setScale] = useState(1.5);
  const [isSelecting, setIsSelecting] = useState(false);
  const [startPos, setStartPos] = useState(null);
  const [selection, setSelection] = useState(selectedArea);

  useEffect(() => {
    if (!pdfUrl) return;

    const loadPdf = async () => {
      try {
        const loadingTask = pdfjsLib.getDocument(pdfUrl);
        const pdf = await loadingTask.promise;
        setPdfDoc(pdf);
        setNumPages(pdf.numPages);
      } catch (error) {
        console.error('Error loading PDF:', error);
      }
    };

    loadPdf();

    return () => {
      if (pdfDoc) {
        pdfDoc.destroy();
      }
    };
  }, [pdfUrl]);

  useEffect(() => {
    if (!pdfDoc) return;
    renderPage(currentPage);
  }, [pdfDoc, currentPage, scale]);

  useEffect(() => {
    if (selection && overlayRef.current) {
      drawSelectionOverlay();
    }
  }, [selection]);

  const renderPage = async (pageNum) => {
    const canvas = canvasRef.current;
    if (!canvas || !pdfDoc) return;

    // Cancel previous render task if still running
    if (renderTaskRef.current) {
      try {
        await renderTaskRef.current.cancel();
      } catch (e) {
        // Ignore cancellation errors
      }
      renderTaskRef.current = null;
    }

    const page = await pdfDoc.getPage(pageNum);
    pageRef.current = page;
    
    const viewport = page.getViewport({ scale });
    viewportRef.current = viewport;

    const context = canvas.getContext('2d');
    canvas.height = viewport.height;
    canvas.width = viewport.width;
    
    // Sync overlay canvas size
    if (overlayRef.current) {
      overlayRef.current.height = viewport.height;
      overlayRef.current.width = viewport.width;
    }

    const renderContext = {
      canvasContext: context,
      viewport: viewport
    };

    renderTaskRef.current = page.render(renderContext);
    
    try {
      await renderTaskRef.current.promise;
      renderTaskRef.current = null;
    } catch (error) {
      if (error.name !== 'RenderingCancelledException') {
        console.error('Error rendering page:', error);
      }
    }
  };

  const drawSelectionOverlay = () => {
    if (!selection || !overlayRef.current) return;
    
    const overlay = overlayRef.current;
    const ctx = overlay.getContext('2d');
    
    // Clear previous selection
    ctx.clearRect(0, 0, overlay.width, overlay.height);
    
    const { x1, y1, x2, y2 } = selection;
    const width = x2 - x1;
    const height = y2 - y1;
    
    // Semi-transparent fill
    ctx.fillStyle = 'rgba(37, 99, 235, 0.08)';
    ctx.fillRect(x1, y1, width, height);
    
    // Dashed border (professional style like Adobe Acrobat)
    ctx.strokeStyle = '#2563eb';
    ctx.lineWidth = 2;
    ctx.setLineDash([8, 4]);
    ctx.strokeRect(x1, y1, width, height);
    ctx.setLineDash([]); // Reset
    
    // Resize handles at 4 corners
    const handleSize = 8;
    ctx.fillStyle = '#2563eb';
    ctx.strokeStyle = '#ffffff';
    ctx.lineWidth = 2;
    
    const corners = [
      [x1, y1],           // Top-left
      [x2, y1],           // Top-right
      [x1, y2],           // Bottom-left
      [x2, y2]            // Bottom-right
    ];
    
    corners.forEach(([cx, cy]) => {
      ctx.fillRect(cx - handleSize/2, cy - handleSize/2, handleSize, handleSize);
      ctx.strokeRect(cx - handleSize/2, cy - handleSize/2, handleSize, handleSize);
    });
    
    // Dimension label
    const widthMm = Math.abs(width / scale * 25.4 / 96).toFixed(1);
    const heightMm = Math.abs(height / scale * 25.4 / 96).toFixed(1);
    const label = `${widthMm} × ${heightMm} mm`;
    
    ctx.font = '12px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif';
    ctx.fillStyle = '#1e40af';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'bottom';
    
    // Background for label
    const textMetrics = ctx.measureText(label);
    const labelX = (x1 + x2) / 2;
    const labelY = y1 - 8;
    const padding = 6;
    
    ctx.fillStyle = '#ffffff';
    ctx.strokeStyle = '#2563eb';
    ctx.lineWidth = 1;
    ctx.fillRect(
      labelX - textMetrics.width/2 - padding,
      labelY - 16,
      textMetrics.width + padding * 2,
      20
    );
    ctx.strokeRect(
      labelX - textMetrics.width/2 - padding,
      labelY - 16,
      textMetrics.width + padding * 2,
      20
    );
    
    // Label text
    ctx.fillStyle = '#1e40af';
    ctx.fillText(label, labelX, labelY);
  };

  const drawSelection = () => {
    // Legacy method - now using overlay
    drawSelectionOverlay();
  };

  const getMousePos = (e) => {
    const canvas = overlayRef.current || canvasRef.current;
    const rect = canvas.getBoundingClientRect();
    
    // Calculate scale factors between actual canvas size and displayed size
    const scaleX = canvas.width / rect.width;
    const scaleY = canvas.height / rect.height;
    
    return {
      x: (e.clientX - rect.left) * scaleX,
      y: (e.clientY - rect.top) * scaleY
    };
  };

  const handleMouseDown = (e) => {
    if (!showSelection) return;
    
    const pos = getMousePos(e);
    setIsSelecting(true);
    setStartPos(pos);
    setSelection(null);
  };

  const handleMouseMove = (e) => {
    if (!isSelecting || !startPos || !showSelection) return;

    const currentPos = getMousePos(e);
    const newSelection = {
      x1: Math.min(startPos.x, currentPos.x),
      y1: Math.min(startPos.y, currentPos.y),
      x2: Math.max(startPos.x, currentPos.x),
      y2: Math.max(startPos.y, currentPos.y)
    };

    setSelection(newSelection);
  };

  const handleMouseUp = (e) => {
    if (!isSelecting || !showSelection) return;

    setIsSelecting(false);
    
    if (selection && pageRef.current && viewportRef.current) {
      // Get page dimensions in PDF points (unscaled)
      const page = pageRef.current;
      const pageHeight = page.view[3]; // PDF page height in points
      
      // Convert canvas coordinates to PDF coordinates
      // Canvas: top-left origin, Y increases downward
      // PDF: bottom-left origin, Y increases upward
      const pdfCoords = {
        page: currentPage - 1, // 0-indexed
        x1: selection.x1 / scale,
        y1: pageHeight - (selection.y2 / scale), // Flip Y and convert
        x2: selection.x2 / scale,
        y2: pageHeight - (selection.y1 / scale)  // Flip Y and convert
      };
      
      console.log('Canvas selection:', selection);
      console.log('Page height:', pageHeight, 'Scale:', scale);
      console.log('PDF coordinates:', pdfCoords);
      
      if (onSelectArea) {
        onSelectArea(pdfCoords);
      }
    }
  };

  const changePage = (delta) => {
    const newPage = currentPage + delta;
    if (newPage >= 1 && newPage <= numPages) {
      setCurrentPage(newPage);
      setSelection(null);
    }
  };

  return (
    <div ref={containerRef} className="pdf-viewer">
      <div className="pdf-controls">
        <button 
          type="button"
          className="btn-control" 
          onClick={() => changePage(-1)} 
          disabled={currentPage <= 1}
        >
          ← Trang trước
        </button>
        <span className="page-info">
          Trang {currentPage} / {numPages}
        </span>
        <button 
          type="button"
          className="btn-control" 
          onClick={() => changePage(1)} 
          disabled={currentPage >= numPages}
        >
          Trang sau →
        </button>
        <button 
          type="button"
          className="btn-control" 
          onClick={() => setScale(scale + 0.2)}
        >
          +
        </button>
        <button 
          type="button"
          className="btn-control" 
          onClick={() => setScale(Math.max(0.5, scale - 0.2))}
        >
          −
        </button>
      </div>
      
      <div className="pdf-canvas-container">
        <div style={{ position: 'relative', display: 'inline-block' }}>
          <canvas
            ref={canvasRef}
            style={{ 
              display: 'block'
            }}
          />
          <canvas
            ref={overlayRef}
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            style={{ 
              position: 'absolute',
              top: 0,
              left: 0,
              cursor: showSelection ? 'crosshair' : 'default',
              pointerEvents: showSelection ? 'auto' : 'none'
            }}
          />
        </div>
        {isSelecting && selection && (
          <div className="selection-debug">
            Canvas: ({Math.round(selection.x1)}, {Math.round(selection.y1)}) → 
            ({Math.round(selection.x2)}, {Math.round(selection.y2)})
          </div>
        )}
      </div>
      
      {showSelection && (
        <div className="selection-hint">
          Nhấn và kéo chuột trên PDF để chọn vị trí hiển thị chữ ký
        </div>
      )}
    </div>
  );
}
