export function getCsrf(){
  const v = document.cookie.match('(^|;)\\s*' + 'csrftoken' + '\\s*=\\s*([^;]+)')
  return v ? v.pop() : ''
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

export async function signPdf(file, creds, options = {}){
  const fd = new FormData(); 
  fd.append('file', file)
  if(creds && creds.username){ 
    fd.append('username', creds.username); 
    fd.append('password', creds.password) 
  }
  // Add signing options
  if(options.reason) fd.append('reason', options.reason)
  if(options.location) fd.append('location', options.location)
  if(options.position) fd.append('position', options.position)
  
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
