import React from "react";

export default function RuleList({rules = [], onToggle}){
  return (
    <div className="card">
      <h2>Rules ({rules.length})</h2>
      <table className="rule-table">
        <thead>
          <tr><th>id</th><th>type</th><th>pattern</th><th>enabled</th><th>actions</th></tr>
        </thead>
        <tbody>
          {rules.map(r => (
            <tr key={r.id}>
              <td>{r.id}</td>
              <td>{r.type}</td>
              <td className="mono">{r.pattern}</td>
              <td>{r.enabled ? "✅" : "⛔"}</td>
              <td>
                <button onClick={()=> onToggle(r.id)}>{r.enabled ? "Disable" : "Enable"}</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
