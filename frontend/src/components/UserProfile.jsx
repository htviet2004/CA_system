import React, { useEffect, useState } from 'react';
import '../static/styles/userinfo.css';
import { updateProfile, fetchProfile } from '../api';

export default function UserInfo({ username, onBack, showMessage }) {
  const [form, setForm] = useState({
    full_name: '',
    phone: '',
    department: '',
    role: '',
    email: '',
  });

  const handleChange = (e) => {
    const { name, value } = e.target;
    setForm((s) => ({ ...s, [name]: value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const payload = { username, ...form };
      const res = await updateProfile(payload);
      console.log('profile update response', res);
      if (showMessage) showMessage('Lưu thông tin thành công', 'success');
    } catch (err) {
      console.error(err);
      if (showMessage) showMessage('Lỗi khi lưu thông tin: ' + (err.message || err), 'error');
    }
  };

  useEffect(() => {
    let mounted = true
    const load = async () => {
      if (!username) return
      try {
        const res = await fetchProfile(username)
        if (!mounted) return
        if (res && res.profile) {
          setForm((s) => ({ ...s, ...res.profile }))
        }
      } catch (err) {
        console.debug('No profile found or fetch error', err)
      }
    }
    load()
    return () => { mounted = false }
  }, [username])

  return (
    <div className="userinfo-container">
      <h2>Chỉnh sửa thông tin người dùng</h2>

      <form onSubmit={handleSubmit} className="userinfo-form">
        <label>
          Full name
          <input
            name="full_name"
            value={form.full_name}
            onChange={handleChange}
            placeholder="Nguyen Van A"
          />
        </label>

        <label>
          Số điện thoại
          <input
            name="phone"
            value={form.phone}
            onChange={handleChange}
            placeholder="09xxxxxxxx"
          />
        </label>

        <label>
          Khoa
          <input
            name="department"
            value={form.department}
            onChange={handleChange}
            placeholder="Khoa Công nghệ Thông tin"
          />
        </label>

        <label>
          Role
          <input
            name="role"
            value={form.role}
            onChange={handleChange}
            placeholder="Ex: Student/Faculty/Staff"
          />
        </label>

        <label>
          Email
          <input
            name="email"
            value={form.email}
            onChange={handleChange}
            placeholder="Ex: nguyenvana@example.com"
          />
        </label>

        <div className="userinfo-actions">
          <button type="button" onClick={onBack}>
            Quay lại
          </button>
          <button type="submit" className="primary">
            Lưu
          </button>
        </div>
      </form>
    </div>
  );
}
