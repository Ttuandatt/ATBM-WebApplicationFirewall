import React from "react";

export default function LogsView({logs = []}){
  return (
    <div className="card">
      <h2>Recent blocked logs</h2>
      <div className="logs">
        {logs.length===0 && <div>No logs yet</div>}
        {logs.map((l, idx) => (
          <div key={idx} className="log-line">
            <div><strong>{l.timestamp || l.time}</strong> — {l.src_ip} → {l.url}</div>
            <div className="mono small">{(l.payload || "").slice(0,200)}{(l.payload || "").length>200 && "..."}</div>
            {l.matched_pattern && <div className="evidence">matched: {l.matched_pattern}</div>}
          </div>
        ))}
      </div>
    </div>
  );
}
