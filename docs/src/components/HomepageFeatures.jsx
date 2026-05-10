import React from 'react';

const FEATURES = [
  { title:'Vollständig Docker-basiert', icon:'🐳',
    desc:'Ein Befehl startet alles. Keine manuelle Installation, keine Abhängigkeiten auf dem Host-System.' },
  { title:'Multi-Tenant & sicher',      icon:'🔒',
    desc:'PostgreSQL Row-Level Security isoliert Mandanten-Daten. JWT + API-Key Authentifizierung.' },
  { title:'MCP-Exposition erkannt',     icon:'🤖',
    desc:'Erkennt unauthentifizierte KI-Agenten-Server (CVE-2025-49596). Attack-Chain-Analyse inklusive.' },
  { title:'6 Security-Tools integriert',icon:'⚡',
    desc:'Subfinder, Naabu, HTTPX, Nuclei, theHarvester, Ramparts — in 5 automatisierten Scan-Phasen.' },
];

export default function HomepageFeatures() {
  return (
    <section style={{ padding:'3rem 2rem', display:'grid',
      gridTemplateColumns:'repeat(auto-fit,minmax(280px,1fr))', gap:'1.25rem',
      maxWidth:1000, margin:'0 auto' }}>
      {FEATURES.map(f => (
        <div key={f.title} style={{
          background:'var(--ifm-background-surface-color)',
          border:'1px solid var(--ifm-color-emphasis-200)',
          borderRadius:8, padding:'1.5rem',
        }}>
          <div style={{ fontSize:'2rem', marginBottom:'0.5rem' }}>{f.icon}</div>
          <h3 style={{ color:'var(--ifm-heading-color)', margin:'0 0 0.5rem' }}>{f.title}</h3>
          <p style={{ color:'var(--ifm-font-color-base)', margin:0, fontSize:'0.9rem' }}>{f.desc}</p>
        </div>
      ))}
    </section>
  );
}
