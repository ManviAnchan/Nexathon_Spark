import React, { useState } from 'react';
import { ArrowRight, Fingerprint, LockKeyhole, Sparkles, User, WifiOff } from 'lucide-react';
import { BrandMark } from './BrandMark';

interface LoginScreenProps { onLogin: (user: { name: string; role: string; airGapped: boolean }) => void; }

export const LoginScreen: React.FC<LoginScreenProps> = ({ onLogin }) => {
  const [name, setName] = useState('adithya');
  const [role, setRole] = useState('Lead Cryptanalyst');
  const [airGapped, setAirGapped] = useState(true);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    onLogin({ name: name.trim(), role, airGapped });
  };

  return <div className="login-theme login-stage">
    <div className="login-brand"><span className="brand-mark"><BrandMark size={21}/></span><span><b>KEYNOVA</b><small>QUANTUM READINESS</small></span></div>
    <div className="login-layout">
      <section className="login-intro">
        <div className="login-orbital" aria-hidden="true"><span className="orbital-core"><Fingerprint size={27}/></span><i/><i/><i/></div>
        <span className="eyebrow"><Sparkles size={13}/> CRYPTOGRAPHY, MADE VISIBLE</span>
        <h1>Prepare your<br/><em>next chapter.</em></h1>
        <p>Understand where today’s cryptography lives, what quantum change means for it, and how to plan the transition with confidence.</p>
        <div className="login-trustline"><span><WifiOff size={14}/> Local analysis</span><i/><span><LockKeyhole size={14}/> Private by design</span></div>
      </section>
      <section className="login-panel">
        <div className="login-panel-head"><span className="eyebrow">ANALYST WORKSPACE</span><h2>Welcome in</h2><p>Set up your local session to continue.</p></div>
        <form onSubmit={handleSubmit} className="login-form">
          <label>Analyst name<div className="login-input-wrap"><User size={15}/><input value={name} onChange={e=>setName(e.target.value)} placeholder="Your name" required/></div></label>
          <label>Workspace role<select value={role} onChange={e=>setRole(e.target.value)}><option value="Lead Cryptanalyst">Lead Cryptanalyst · Full access</option><option value="SecOps Engineer">SecOps Engineer · Audit & ingestion</option><option value="Compliance Officer">Compliance Officer · Read only</option></select></label>
          <label className="local-session-toggle"><input type="checkbox" checked={airGapped} onChange={e=>setAirGapped(e.target.checked)}/><span className="toggle-track"><i/></span><span><b>Local-only session</b><small>Keep analysis on this machine</small></span></label>
          <button className="login-continue" type="submit">Open workspace <ArrowRight size={15}/></button>
        </form>
        <div className="login-panel-foot"><span className="status-dot-small"/> SESSION INITIALIZED LOCALLY</div>
      </section>
    </div>
    <footer className="login-footer"><span>KEYNOVA <i/> CRYPTOGRAPHIC DISCOVERY</span><span>DESIGNED FOR THE POST-QUANTUM TRANSITION</span></footer>
  </div>;
};
