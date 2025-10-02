const API = "http://127.0.0.1:5002/api"; // admin_api.py chạy ở cổng này

async function fetchRules() {
  const res = await fetch(`${API}/rules`);
  const data = await res.json();
  const tbody = document.querySelector("#rulesTable tbody");
  tbody.innerHTML = "";
  data.forEach(r => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${r.id}</td>
      <td>${r.type}</td>
      <td><code>${r.pattern}</code></td>
      <td>${r.enabled}</td>
      <td>${r.source}</td>
    `;
    tbody.appendChild(tr);
  });
}

async function fetchLogs() {
  const res = await fetch(`${API}/logs`);
  const data = await res.json();
  document.querySelector("#logsBox").textContent = JSON.stringify(data, null, 2);
}

async function runAnalyzer() {
  const res = await fetch(`${API}/analyze`, { method: "POST" });
  const data = await res.json();
  document.querySelector("#analyzerOutput").textContent = JSON.stringify(data, null, 2);
}
