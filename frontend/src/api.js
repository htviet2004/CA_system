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

export async function signPdf(file, creds){
  const fd = new FormData(); fd.append('file', file)
  if(creds && creds.username){ fd.append('username', creds.username); fd.append('password', creds.password) }
  const res = await fetch('/api/sign/', {method:'POST', body:fd, credentials:'include', headers:{'X-CSRFToken': getCsrf()}})
  if(!res.ok){ const txt = await res.text(); throw new Error(txt) }
  const blob = await res.blob()
  return blob
}
