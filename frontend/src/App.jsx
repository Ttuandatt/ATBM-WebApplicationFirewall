import React, { useEffect, useState } from "react";
import RuleList from "./components/RuleList";
import LogsView from "./components/LogsView";
import AnalyzerPanel from "./components/AnalyzerPanel";

const API_BASE = "http://127.0.0.1:5002";

export default function App(){
  const [rules, setRules] = useState([]);
  const [logs, setLogs] = useState([]);

  const fetchRules = async () => {
    try{
      const r = await fetch(API_BASE + "/rules");
      const j = await r.json();
      setRules(j);
    }catch(e){
      console.error(e);
    }
  };

  const fetchLogs = async () => {
    try{
      const r = await fetch(API_BASE + "/logs/recent?limit=50");
      const j = await r.json();
      setLogs(j);
    }catch(e){
      console.error(e);
    }
  };

  useEffect(() => {
    fetchRules();
    fetchLogs();
    const t = setInterval(()=> {
      fetchRules();
      fetchLogs();
    }, 5000);
    return ()=> clearInterval(t);
  }, []);

  return (
    <div className="container">
      <header>
        <h1>RuleForge — Admin Demo</h1>
        <p className="tagline">Rule-based detection with automatic rule generation</p>
      </header>

      <main>
        <section className="left">
          <AnalyzerPanel onRun={()=> { fetchRules(); fetchLogs(); }} />
          <RuleList rules={rules} onToggle={async (id)=> {
            await fetch(`${API_BASE}/rules/${id}/toggle`, {method: "POST"});
            await fetchRules();
          }} />
        </section>

        <section className="right">
          <LogsView logs={logs} />
        </section>
      </main>

      <footer>
        <small>Demo — not for production. Auto-enable should be off in real deployments.</small>
      </footer>
    </div>
  );
}
