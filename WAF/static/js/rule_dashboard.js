// ======== Helpers ========
const modal = document.getElementById('modal');
const ruleNameInput = document.getElementById('rule-name');
const rulePatternInput = document.getElementById('rule-pattern');
const ruleSourceInput = document.getElementById('rule-source');
const ruleAttackTypeInput = document.getElementById('rule-attack-type');
const ruleSeverityInput = document.getElementById('rule-severity');
const ruleDescriptionInput = document.getElementById('rule-description');
let editPattern = null;

// Toast notification - IMPROVED
function showToast(msg, type="success"){
    const toast = document.getElementById("toast");
    toast.textContent = msg;
    toast.className = `toast show ${type}`;
    console.log(`[Toast] ${type}: ${msg}`); // Debug log
    setTimeout(()=>{
        toast.className="toast";
    }, 3000);
}

// ======== Load rules - FIXED with cache busting ========
async function loadRules(query="", attack_type=""){
    try{
        // Add timestamp to prevent browser caching
        const timestamp = new Date().getTime();
        const url = `/api/rules/search?q=${encodeURIComponent(query)}&type=${encodeURIComponent(attack_type)}&_t=${timestamp}`;

        console.log(`[Load Rules] Fetching: ${url}`); // Debug log

        const res = await fetch(url, {
            method: 'GET',
            headers: {
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            }
        });

        const data = await res.json();
        const tbody = document.querySelector('#rules-table tbody');
        tbody.innerHTML="";

        if(data.success){
            console.log(`[Load Rules] Loaded ${data.data.length} rules`); // Debug log
            data.data.forEach(rule=>{
                const tr = document.createElement('tr');
                tr.innerHTML=`
                    <td>${escapeHtml(rule.name)}</td>
                    <td><code>${escapeHtml(rule.pattern)}</code></td>
                    <td><span class="badge ${rule.attack_type}">${rule.attack_type}</span></td>
                    <td>${escapeHtml(rule.source||'')}</td>
                    <td>${rule.severity||''}</td>
                    <td>${escapeHtml(rule.description||'')}</td>
                    <td>
                        <button class="edit-btn">Edit</button>
                        <button class="delete-btn">Delete</button>
                    </td>
                `;
                tr.querySelector('.edit-btn').onclick = () => openModal(rule);
                tr.querySelector('.delete-btn').onclick = () => deleteRule(rule.pattern);
                tbody.appendChild(tr);
            });
        } else {
            showToast("❌ Failed to load rules: " + (data.message || "Unknown error"), "error");
        }
    } catch(err){
        showToast("❌ Error loading rules", "error");
        console.error("[Load Rules Error]:", err);
    }
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return String(text).replace(/[&<>"']/g, m => map[m]);
}

// ======== Modal ========
function openModal(rule=null){
    if(rule){
        ruleNameInput.value=rule.name;
        rulePatternInput.value=rule.pattern;
        ruleSourceInput.value=rule.source||"custom";
        ruleAttackTypeInput.value=rule.attack_type;
        ruleSeverityInput.value=rule.severity||"medium";
        ruleDescriptionInput.value=rule.description||"";
        editPattern=rule.pattern;
    }else{
        ruleNameInput.value="";
        rulePatternInput.value="";
        ruleSourceInput.value="custom";
        ruleAttackTypeInput.value="MANUAL";
        ruleSeverityInput.value="medium";
        ruleDescriptionInput.value="";
        editPattern=null;
    }
    modal.style.display="block";
}

document.getElementById('btn-add').onclick=()=>openModal();
document.getElementById('modal-cancel').onclick=()=>{
    modal.style.display="none";
    editPattern=null;
};

// Close modal when clicking outside
window.onclick = function(event) {
    if (event.target === modal) {
        modal.style.display = "none";
        editPattern=null;
    }
}

// ======== Save rule - FIXED ========
document.getElementById('modal-save').onclick = async () => {
    const payload = {
        name: ruleNameInput.value.trim(),
        pattern: rulePatternInput.value.trim(),
        source: ruleSourceInput.value.trim(),
        attack_type: ruleAttackTypeInput.value,
        severity: ruleSeverityInput.value,
        description: ruleDescriptionInput.value.trim()
    };

    if(!payload.name || !payload.pattern){
        showToast("❌ Name and pattern required!", "error");
        return;
    }

    const saveBtn = document.getElementById('modal-save');
    const originalText = saveBtn.innerText;
    saveBtn.disabled = true;
    saveBtn.innerText = "Saving...";

    try {
        console.log('[Save Rule] Starting save process...'); // Debug log

        // If editing and pattern changed, delete old rule first
        if(editPattern && editPattern !== payload.pattern){
            console.log(`[Save Rule] Deleting old pattern: ${editPattern}`);
            await fetch('/api/rules/delete', {
                method:'DELETE',
                headers:{'Content-Type':'application/json'},
                body:JSON.stringify({pattern: editPattern})
            });
        } else if (editPattern && editPattern === payload.pattern) {
            console.log(`[Save Rule] Updating existing pattern: ${editPattern}`);
            await fetch('/api/rules/delete', {
                method:'DELETE',
                headers:{'Content-Type':'application/json'},
                body:JSON.stringify({pattern: editPattern})
            });
        }

        // Add the new/updated rule
        console.log('[Save Rule] Adding rule:', payload);
        const res = await fetch('/api/rules/add', {
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify(payload)
        });

        const data = await res.json();
        console.log('[Save Rule] Response:', data); // Debug log

        if(data.success){
            console.log('[Save Rule] Success! Closing modal and showing toast...');

            // Close modal first
            modal.style.display = "none";
            editPattern = null;

            // Show success toast
            showToast("✅ Rule saved successfully!", "success");

            // Wait a bit for backend to finish writing to file
            await new Promise(resolve => setTimeout(resolve, 300));

            // Reload rules with cache busting
            console.log('[Save Rule] Reloading rules...');
            await loadRules();

            console.log('[Save Rule] Complete!');
        } else {
            showToast("❌ " + (data.message || "Failed to save rule"), "error");
        }
    } catch(err){
        showToast("❌ Error saving rule", "error");
        console.error("[Save Rule Error]:", err);
    } finally {
        saveBtn.disabled = false;
        saveBtn.innerText = originalText;
    }
};

// ======== Delete rule - FIXED ========
async function deleteRule(pattern){
    if(!confirm("Are you sure you want to delete this rule?")) return;

    try{
        console.log(`[Delete Rule] Deleting: ${pattern}`);
        const res = await fetch('/api/rules/delete',{
            method:'DELETE',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({pattern})
        });
        const data=await res.json();

        if(data.success){
            showToast("✅ Rule deleted successfully", "success");

            // Wait a bit for backend to finish
            await new Promise(resolve => setTimeout(resolve, 300));

            await loadRules();
        }else{
            showToast("❌ " + (data.message || "Failed to delete"), "error");
        }
    }catch(err){
        showToast("❌ Error deleting rule", "error");
        console.error("[Delete Rule Error]:", err);
    }
}

// ======== Import/Export/Reload - FIXED ========
document.getElementById('btn-import').onclick=async ()=>{
    const jsonText=prompt("Paste JSON rules to import:");
    if(!jsonText) return;

    try{
        const rules=JSON.parse(jsonText);
        const res=await fetch('/api/rules/import',{
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({rules,mode:"merge"})
        });
        const data=await res.json();

        if(data.success){
            showToast("✅ Rules imported successfully!", "success");

            // Wait for backend to finish
            await new Promise(resolve => setTimeout(resolve, 300));

            await loadRules();
        }else{
            showToast("❌ " + (data.message || "Failed to import"), "error");
        }
    }catch(err){
        showToast("❌ Invalid JSON format", "error");
        console.error("[Import Error]:", err);
    }
};

document.getElementById('btn-export').onclick=async ()=>{
    try{
        const res=await fetch('/api/rules/export');
        const data=await res.json();

        if(data.success || data.data){
            // Download as file
            const blob = new Blob([JSON.stringify(data.data || data, null, 2)], {type: 'application/json'});
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `waf_rules_${new Date().getTime()}.json`;
            a.click();
            window.URL.revokeObjectURL(url);

            showToast("✅ Rules exported successfully!", "success");
            console.log("Exported rules:", data);
        } else {
            showToast("❌ Failed to export rules", "error");
        }
    }catch(err){
        showToast("❌ Error exporting rules", "error");
        console.error("[Export Error]:", err);
    }
};

document.getElementById('btn-reload').onclick=async ()=>{
    try{
        console.log('[Reload] Starting reload...');
        const res=await fetch('/api/rules/reload',{
            method:'POST',
            headers: {
                'Cache-Control': 'no-cache'
            }
        });
        const data=await res.json();

        if(data.success){
            showToast("✅ Rules reloaded successfully!", "success");

            // Wait for backend to finish
            await new Promise(resolve => setTimeout(resolve, 300));

            await loadRules();
        }else{
            showToast("❌ " + (data.message || "Failed to reload"), "error");
        }
    }catch(err){
        showToast("❌ Error reloading rules", "error");
        console.error("[Reload Error]:", err);
    }
};

// ======== Search ========
document.getElementById('btn-search').onclick=()=>{
    const q=document.getElementById('search-keyword').value;
    const t=document.getElementById('filter-attack-type').value;
    console.log(`[Search] Query: "${q}", Type: "${t}"`);
    loadRules(q,t);
};

// Allow Enter key to trigger search
document.getElementById('search-keyword').addEventListener('keypress', (e) => {
    if(e.key === 'Enter'){
        document.getElementById('btn-search').click();
    }
});

// ======== Initial load ========
document.addEventListener('DOMContentLoaded', () => {
    console.log('[Init] Loading rules on page load...');
    loadRules();
});