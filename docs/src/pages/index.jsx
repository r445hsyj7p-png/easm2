import React from 'react';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import HomepageFeatures from '@site/src/components/HomepageFeatures';

export default function Home() {
  const {siteConfig} = useDocusaurusContext();
  return (
    <Layout title="EASM Platform" description="External Attack Surface Management for MSSPs">
      <header style={{
        background:'linear-gradient(180deg,#050810 0%,#0d1221 100%)',
        padding:'4rem 2rem 3rem', textAlign:'center',
        borderBottom:'1px solid #1e2d45',
      }}>
        <h1 style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:'2.5rem',
          color:'#f1f5f9', marginBottom:'0.75rem' }}>
          EASM MSSP Platform
        </h1>
        <p style={{ fontSize:'1.15rem', color:'#94a3b8', maxWidth:600, margin:'0 auto 2rem' }}>
          External Attack Surface Management für Managed Security Service Provider.
          Vollständig Docker-basiert. Ein Befehl reicht.
        </p>
        <div style={{ display:'flex', gap:'1rem', justifyContent:'center', flexWrap:'wrap' }}>
          <Link className="button button--primary button--lg"
            to="/getting-started/installation">
            Quick Start →
          </Link>
          <Link className="button button--secondary button--lg"
            to="/architecture/overview">
            Architektur
          </Link>
        </div>
        <div style={{ marginTop:'2rem', fontFamily:"'JetBrains Mono',monospace",
          fontSize:'0.85rem', color:'#475569',
          background:'#0d1221', border:'1px solid #1e2d45',
          borderRadius:6, padding:'1rem 1.5rem', display:'inline-block', textAlign:'left' }}>
          <span style={{color:'#22c55e'}}>$</span> git clone https://github.com/your-org/easm-platform<br/>
          <span style={{color:'#22c55e'}}>$</span> cp .env.example .env  <span style={{color:'#475569'}}># Passwörter setzen</span><br/>
          <span style={{color:'#22c55e'}}>$</span> docker compose up -d  <span style={{color:'#475569'}}># Fertig</span>
        </div>
      </header>
      <main>
        <HomepageFeatures />
      </main>
    </Layout>
  );
}
