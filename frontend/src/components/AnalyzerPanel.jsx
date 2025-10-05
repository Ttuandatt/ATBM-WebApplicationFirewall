import React, { useState } from "react";
const API_BASE = "http://127.0.0.1:5002/api";

export default function AnalyzerPanel({onRun}){
  const [running, setRunning] = useState(false);
  const [output, setOutput] = useState("");

  const runAnalyzer = async () => {
    setRunning(true);
    setOutput("running...");
    try{
      const r = await fetch(API_BASE + "/analyzer/run", {method: "POST"});
      const j = await r.json();
      setOutput(JSON.stringify(j, null, 2));
      if(onRun) onRun();
    }catch(e){
      setOutput("error: " + e.toString());
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="card">
      <h2>Analyzer</h2>
      <p>Scan recent logs and auto-generate candidate rules.</p>
      <button onClick={runAnalyzer} disabled={running}>{running ? "Running..." : "Run analyzer"}</button>
      <pre className="output">{output}</pre>
    </div>
  );
}
