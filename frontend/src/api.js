export function getCsrf(){
  const v = document.cookie.match('(^|;)\\s*' + 'csrftoken' + '\\s*=\\s*([^;]+)')
  return v ? v.pop() : ''
}

/**
 * AUTHENTICATION API
 * Uses Django session cookies (HttpOnly) for security.
 * Session persists across page reloads.
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
  return res.json()
}

export async function register(username, password){
  const fd = new FormData(); fd.append('username', username); fd.append('password', password)
  const res = await fetch('/api/sign/register/', {method:'POST', body:fd, credentials:'include', headers:{'X-CSRFToken': getCsrf()}})
  if(!res.ok) throw new Error(await res.text())
  return res.json()
}

export async function login(username, password){
  const fd = new FormData(); fd.append('username', username); fd.append('password', password)
  const res = await fetch('/api/sign/login/', {method:'POST', body:fd, credentials:'include', headers:{'X-CSRFToken': getCsrf()}})
  if(!res.ok) throw new Error(await res.text())
  return res.json()
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
  if(options.location) fd.append('location', options.location)
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
