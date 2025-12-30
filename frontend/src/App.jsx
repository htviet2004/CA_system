import React, { useState } from 'react'
import { register, login, signPdf } from './api'

export default function App(){
  const [msg, setMsg] = useState('')
  const [logged, setLogged] = useState({username:'', password:''})

  async function handleRegister(e){
    e.preventDefault()
    const u = e.target.username.value
    const p = e.target.password.value
    try{
      await register(u,p)
      setMsg('Registered '+u)
    }catch(err){ setMsg('Register error: '+(err.message||err)) }
  }

  async function handleLogin(e){
    e.preventDefault()
    const u = e.target.username.value
    const p = e.target.password.value
    try{
      await login(u,p)
      setLogged({username:u,password:p})
      setMsg('Logged in '+u)
    }catch(err){ setMsg('Login error: '+(err.message||err)) }
  }

  async function handleSign(e){
    e.preventDefault()
    const file = e.target.file.files[0]
    if(!file){ setMsg('Select a PDF file'); return }
    try{
      const blob = await signPdf(file, logged)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = (file.name.replace(/\.pdf$/i,'')||'signed') + '_signed.pdf'
      a.click()
      setMsg('Signed successfully')
    }catch(err){ setMsg('Sign error: '+(err.message||err)) }
  }

  return (
    <div className="container">
      <div className="header">
        <div className="brand">
          <span className="logo" />
          <div>
            <div className="title">CA System — PDF Signing</div>
            <div className="muted">Issue, sign and verify PDFs with internal CA</div>
          </div>
        </div>
        <div>
          {logged.username ? <div className="muted">Signed in as <strong>{logged.username}</strong></div> : <div className="muted">Not signed in</div>}
        </div>
      </div>

      <div className="card grid">
        <section>
          <h3>Register</h3>
          <form onSubmit={handleRegister}>
            <input name="username" placeholder="username" required />
            <input name="password" type="password" placeholder="password" required />
            <button type="submit">Create account</button>
          </form>
        </section>

        <section>
          <h3>Login</h3>
          <form onSubmit={handleLogin}>
            <input name="username" placeholder="username" required />
            <input name="password" type="password" placeholder="password" required />
            <button type="submit" className="secondary">Login</button>
          </form>
        </section>
      </div>

      <div className="card">
        <h3>Sign PDF</h3>
        <form onSubmit={handleSign}>
          <input type="file" name="file" accept="application/pdf" />
          <div style={{marginTop:8}}>
            <button type="submit">Sign file</button>

          </div>
        </form>
      </div>

      <div className="msg">{msg}</div>
    </div>
  )
}
