// CSRF Token state - stored after login
let storedCsrfToken = '';

export function getCsrf(){
  // 1. Check if token was saved from login response
  if(storedCsrfToken) return storedCsrfToken;
  
  // 2. Try to get from cookie (set by Django after login)
  const v = document.cookie.match('(^|;)\\s*' + 'csrftoken' + '\\s*=\\s*([^;]+)')
  if(v) return v.pop();
  
  // 3. Return empty (login/register will work without token)
  return ''
}

function setStoredCsrf(token){
  storedCsrfToken = token;
}

/**
 * AUTHENTICATION API
 * Uses Django session cookies (HttpOnly) for security.
 * Session persists across page reloads.
 * CSRF tokens are exchanged during login.
 */

export async function getCurrentUser(){
  const res = await fetch('/api/usermanage/me/', {
    method: 'GET',
    credentials: 'include'
  })
  if(!res.ok) throw new Error('Failed to get current user')
  return res.json()
}

export async function logout(){
  const res = await fetch('/api/usermanage/logout/', {
    method: 'POST',
    credentials: 'include',
    headers: {'X-CSRFToken': getCsrf()}
  })
  if(!res.ok) throw new Error('Logout failed')
  storedCsrfToken = '';  // Clear stored token on logout
  return res.json()
}

export async function register(username, password, profileData = {}){
  const fd = new FormData(); 
  fd.append('username', username); 
  fd.append('password', password)
  
  // Add profile data fields if provided
  if (profileData.full_name) fd.append('full_name', profileData.full_name);
  if (profileData.email) fd.append('email', profileData.email);
  if (profileData.phone) fd.append('phone', profileData.phone);
  if (profileData.department) fd.append('department', profileData.department);
  if (profileData.role) fd.append('role', profileData.role);
  
  const res = await fetch('/api/usermanage/register/', {
    method:'POST', 
    body:fd, 
    credentials:'include'
    // No X-CSRFToken needed for register (no prior session)
  })
  if(!res.ok) {
    const data = await res.json().catch(() => ({ error: 'Đăng ký thất bại' }));
    throw new Error(data.error || 'Đăng ký thất bại');
  }
  const data = await res.json()
  // Save CSRF token if returned (for post-register operations)
  if(data.csrf_token) setStoredCsrf(data.csrf_token);
  return data;
}

export async function login(username, password){
  const fd = new FormData(); 
  fd.append('username', username); 
  fd.append('password', password)
  const res = await fetch('/api/usermanage/login/', {
    method:'POST', 
    body:fd, 
    credentials:'include'
    // No X-CSRFToken needed for login (no prior session)
  })
  if(!res.ok) throw new Error(await res.text())
  const data = await res.json()
  // Save CSRF token from login response for subsequent requests
  if(data.csrf_token) setStoredCsrf(data.csrf_token);
  return data;
}

/**
 * PDF SIGNING API
 * Note: After session is established, credentials are optional
 * as backend can use request.user from session
 */
export async function signPdf(file, creds, options = {}){
  const fd = new FormData(); 
  fd.append('file', file)
  // Send credentials for now (backward compatibility)
  // TODO: Backend should use request.user when session exists
  if(creds && creds.username){ 
    fd.append('username', creds.username); 
    fd.append('password', creds.password) 
  }

  if(options.reason) fd.append('reason', options.reason)
  if(options.position) fd.append('position', options.position)

  if(options.signer_name) fd.append('signer_name', options.signer_name)
  if(options.title) fd.append('title', options.title)
  if(options.custom_text) fd.append('custom_text', options.custom_text)
  
  const res = await fetch('/api/sign/', {
    method:'POST', 
    body:fd, 
    credentials:'include', 
    headers:{'X-CSRFToken': getCsrf()}
  })
  if(!res.ok){ 
    const txt = await res.text(); 
    throw new Error(txt) 
  }
  const blob = await res.blob()
  return blob
}

export async function updateProfile(payload){
  const res = await fetch('/api/usermanage/profile/update/', {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': getCsrf(),
    },
    body: JSON.stringify(payload),
  })
  if(!res.ok){
    const txt = await res.text()
    throw new Error(txt)
  }
  return res.json()
}

export async function fetchProfile(username){
  const res = await fetch(`/api/usermanage/profile/${encodeURIComponent(username)}/`, {
    method: 'GET',
    credentials: 'include'
  })
  if(!res.ok){
    const txt = await res.text()
    throw new Error(txt)
  }
  return res.json()
}

/**
 * META API
 * Fetch dropdown options for forms
 */
export async function fetchRoles() {
  const res = await fetch('/api/usermanage/meta/roles/', {
    method: 'GET',
    credentials: 'include'
  })
  if (!res.ok) {
    throw new Error('Failed to fetch roles')
  }
  return res.json()
}

export async function fetchDepartments() {
  const res = await fetch('/api/usermanage/meta/departments/', {
    method: 'GET',
    credentials: 'include'
  })
  if (!res.ok) {
    throw new Error('Failed to fetch departments')
  }
  return res.json()
}

export async function fetchAllMeta() {
  const res = await fetch('/api/usermanage/meta/all/', {
    method: 'GET',
    credentials: 'include'
  })
  if (!res.ok) {
    throw new Error('Failed to fetch meta data')
  }
  return res.json()
}

/**
 * SIGNING HISTORY API
 * Get user's signing history for audit trail
 */
export async function getSigningHistory(page = 1, limit = 50) {
  const offset = (page - 1) * limit
  const res = await fetch(`/api/usercerts/history/?limit=${limit}&offset=${offset}`, {
    method: 'GET',
    credentials: 'include'
  })
  if (!res.ok) {
    const txt = await res.text()
    throw new Error(txt)
  }
  return res.json()
}

/**
 * SIGNED DOCUMENTS API
 * List and download signed PDFs stored on server
 */
export async function getSignedDocuments(page = 1, perPage = 20, filters = {}) {
  const params = new URLSearchParams({
    page: page.toString(),
    limit: perPage.toString()
  })
  
  if (filters.status) params.append('status', filters.status)
  if (filters.search) params.append('search', filters.search)
  if (filters.downloadable_only) params.append('downloadable_only', 'true')
  
  const res = await fetch(`/api/sign/history/?${params}`, {
    method: 'GET',
    credentials: 'include'
  })
  if (!res.ok) {
    const txt = await res.text()
    throw new Error(txt)
  }
  return res.json()
}

export async function getSignedDocumentDetail(documentId) {
  const res = await fetch(`/api/sign/history/${documentId}/`, {
    method: 'GET',
    credentials: 'include'
  })
  if (!res.ok) {
    if (res.status === 404) throw new Error('Tài liệu không tồn tại')
    const txt = await res.text()
    throw new Error(txt)
  }
  return res.json()
}

export async function downloadSignedDocument(documentId) {
  const res = await fetch(`/api/sign/history/${documentId}/download/`, {
    method: 'GET',
    credentials: 'include'
  })
  if (!res.ok) {
    if (res.status === 410) throw new Error('Tài liệu đã hết hạn lưu trữ')
    if (res.status === 404) throw new Error('Tài liệu không tồn tại')
    const txt = await res.text()
    throw new Error(txt)
  }
  return res.blob()
}

export async function getSigningHistoryStats() {
  const res = await fetch('/api/sign/history/stats/', {
    method: 'GET',
    credentials: 'include'
  })
  if (!res.ok) {
    const txt = await res.text()
    throw new Error(txt)
  }
  return res.json()
}

export async function getSigningStats() {
  const res = await fetch('/api/usercerts/signing-stats/', {
    method: 'GET',
    credentials: 'include'
  })
  if (!res.ok) {
    const txt = await res.text()
    throw new Error(txt)
  }
  return res.json()
}

/**
 * CERTIFICATE API
 * Certificate information, status, and management
 */
export async function getCertificateInfo() {
  const res = await fetch('/api/usercerts/certificate-info/', {
    method: 'GET',
    credentials: 'include'
  })
  if (!res.ok) {
    const txt = await res.text()
    throw new Error(txt)
  }
  return res.json()
}

export async function downloadCertificate(format = 'p12') {
  const res = await fetch(`/api/usercerts/download/?format=${format}`, {
    method: 'GET',
    credentials: 'include'
  })
  if (!res.ok) {
    const txt = await res.text()
    throw new Error(txt)
  }
  return res.blob()
}

export async function renewCertificate() {
  const res = await fetch('/api/usercerts/renew/', {
    method: 'POST',
    credentials: 'include',
    headers: { 'X-CSRFToken': getCsrf() }
  })
  if (!res.ok) {
    const txt = await res.text()
    throw new Error(txt)
  }
  return res.json()
}

/**
 * USER DASHBOARD DATA
 * Combined data for user dropdown
 */
export async function getUserDashboardData() {
  const res = await fetch('/api/usermanage/dashboard/', {
    method: 'GET',
    credentials: 'include'
  })
  if (!res.ok) {
    const txt = await res.text()
    throw new Error(txt)
  }
  return res.json()
}

/**
 * PASSWORD MANAGEMENT
 */
export async function changePassword(currentPassword, newPassword) {
  const res = await fetch('/api/usermanage/change-password/', {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': getCsrf()
    },
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword })
  })
  if (!res.ok) {
    const txt = await res.text()
    throw new Error(txt)
  }
  return res.json()
}

/**
 * ADMIN-ONLY CERTIFICATE MANAGEMENT
 * These functions require admin privileges
 */

export async function adminListAllCertificates(filters = {}) {
  const params = new URLSearchParams()
  if (filters.status) params.append('status', filters.status)
  if (filters.username) params.append('username', filters.username)
  
  const res = await fetch(`/api/usercerts/admin/all-certificates/?${params}`, {
    method: 'GET',
    credentials: 'include'
  })
  if (!res.ok) {
    const txt = await res.text()
    throw new Error(txt)
  }
  return res.json()
}

// Alias for AdminCertificatesTab component compatibility
export async function getAdminCertificates(params = {}) {
  const searchParams = new URLSearchParams()
  if (params.page) searchParams.append('page', params.page.toString())
  if (params.per_page) searchParams.append('per_page', params.per_page.toString())
  if (params.search) searchParams.append('username', params.search)
  if (params.status) searchParams.append('status', params.status)
  
  const res = await fetch(`/api/usercerts/admin/all-certificates/?${searchParams}`, {
    method: 'GET',
    credentials: 'include'
  })
  if (!res.ok) {
    const txt = await res.text()
    throw new Error(txt)
  }
  const data = await res.json()
  // Transform response to match expected format
  return {
    certificates: data.certificates || [],
    pagination: {
      total: data.total_count || 0,
      total_pages: Math.ceil((data.total_count || 0) / (params.per_page || 10))
    }
  }
}

export async function adminReissueCertificate(userId, reason = '', notes = '') {
  const fd = new FormData()
  fd.append('reason', reason)
  fd.append('notes', notes)
  
  const res = await fetch(`/api/usercerts/admin/reissue/${userId}/`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'X-CSRFToken': getCsrf() },
    body: fd
  })
  if (!res.ok) {
    const txt = await res.text()
    throw new Error(txt)
  }
  return res.json()
}

export async function adminForceRenewCertificate(certId, reason = '', notes = '') {
  const fd = new FormData()
  fd.append('reason', reason)
  fd.append('notes', notes)
  
  const res = await fetch(`/api/usercerts/admin/force-renew/${certId}/`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'X-CSRFToken': getCsrf() },
    body: fd
  })
  if (!res.ok) {
    const txt = await res.text()
    throw new Error(txt)
  }
  return res.json()
}

// Alias for AdminCertificatesTab compatibility
export async function adminRenewCertificate(certId, reason = '', notes = '') {
  return adminForceRenewCertificate(certId, reason, notes)
}

export async function adminRevokeCertificate(certId, reason = 'unspecified') {
  const fd = new FormData()
  fd.append('reason', reason)
  
  const res = await fetch(`/api/usercerts/revoke/${certId}/`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'X-CSRFToken': getCsrf() },
    body: fd
  })
  if (!res.ok) {
    const txt = await res.text()
    throw new Error(txt)
  }
  return res.json()
}

/**
 * ADMIN STATS API
 */
export async function getAdminStats() {
  const res = await fetch('/api/usermanage/admin/stats/', {
    method: 'GET',
    credentials: 'include'
  })
  if (!res.ok) {
    const txt = await res.text()
    throw new Error(txt)
  }
  return res.json()
}

/**
 * ADMIN USER MANAGEMENT API
 */
export async function getAdminUsers(params = {}) {
  const searchParams = new URLSearchParams()
  if (params.page) searchParams.append('page', params.page.toString())
  if (params.per_page) searchParams.append('per_page', params.per_page.toString())
  if (params.search) searchParams.append('search', params.search)
  if (params.status) searchParams.append('status', params.status)
  if (params.role) searchParams.append('role', params.role)
  
  const res = await fetch(`/api/usermanage/admin/users/?${searchParams}`, {
    method: 'GET',
    credentials: 'include'
  })
  if (!res.ok) {
    const txt = await res.text()
    throw new Error(txt)
  }
  return res.json()
}

export async function getAdminUser(userId) {
  const res = await fetch(`/api/usermanage/admin/users/${userId}/`, {
    method: 'GET',
    credentials: 'include'
  })
  if (!res.ok) {
    const txt = await res.text()
    throw new Error(txt)
  }
  return res.json()
}

export async function createAdminUser(userData) {
  const res = await fetch('/api/usermanage/admin/users/create/', {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': getCsrf()
    },
    body: JSON.stringify(userData)
  })
  if (!res.ok) {
    const txt = await res.text()
    throw new Error(txt)
  }
  return res.json()
}

export async function updateAdminUser(userId, userData) {
  const res = await fetch(`/api/usermanage/admin/users/${userId}/update/`, {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': getCsrf()
    },
    body: JSON.stringify(userData)
  })
  if (!res.ok) {
    const txt = await res.text()
    throw new Error(txt)
  }
  return res.json()
}

export async function deleteAdminUser(userId) {
  const res = await fetch(`/api/usermanage/admin/users/${userId}/delete/`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'X-CSRFToken': getCsrf() }
  })
  if (!res.ok) {
    const txt = await res.text()
    throw new Error(txt)
  }
  return res.json()
}

export async function getAdminMeta() {
  // Use existing meta endpoint
  return fetchAllMeta()
}

/**
 * ADMIN SIGNING HISTORY API
 */
export async function getAdminSigningHistory(params = {}) {
  const searchParams = new URLSearchParams()
  if (params.page) searchParams.append('page', params.page.toString())
  if (params.per_page) searchParams.append('per_page', params.per_page.toString())
  if (params.search) searchParams.append('search', params.search)
  if (params.status) searchParams.append('status', params.status)
  if (params.username) searchParams.append('username', params.username)
  
  const res = await fetch(`/api/usermanage/admin/signing-history/?${searchParams}`, {
    method: 'GET',
    credentials: 'include'
  })
  if (!res.ok) {
    const txt = await res.text()
    throw new Error(txt)
  }
  return res.json()
}

export async function adminRevokeSignature(signatureId, reason = '') {
  const fd = new FormData()
  fd.append('reason', reason)
  
  const res = await fetch(`/api/usercerts/history/${signatureId}/revoke/`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'X-CSRFToken': getCsrf() },
    body: fd
  })
  if (!res.ok) {
    const txt = await res.text()
    throw new Error(txt)
  }
  return res.json()
}
