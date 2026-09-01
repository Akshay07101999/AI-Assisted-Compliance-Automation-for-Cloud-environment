// ── State ─────────────────────────────────────────────────────────────────────
let dashboardData = null;
let scanPoller    = null;

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    fetchReport();
});

// ── API Calls ─────────────────────────────────────────────────────────────────

async function fetchReport() {
    try {
        const res = await fetch('/api/report');

        if (res.status === 404) {
            // No report yet — clean empty state
            renderEmptyState("No scan report found. Click 'Run Scan' to run a live AWS scan.");
            return;
        }

        if (!res.ok) throw new Error(`HTTP ${res.status}`);

        dashboardData = await res.json();
        renderDashboard();
    } catch (e) {
        console.error("Failed to fetch report:", e);
        renderEmptyState("Could not connect to the dashboard server. Is server.py running?");
    }
}

async function triggerScan() {
    const btn = document.querySelector('.btn-primary');
    btn.disabled  = true;
    btn.innerText = '⏳ Scanning…';

    showToast("⏳ Triggering live AWS scan...");

    try {
        const res = await fetch('/api/scan', { method: 'POST' });
        const data = await res.json();

        if (res.status === 409) {
            showToast("⚠️ Scan already in progress.");
            btn.disabled  = false;
            btn.innerText = 'Run Scan';
            return;
        }

        // Start polling status
        startStatusPolling(btn);

    } catch (e) {
        showToast("❌ Failed to trigger scan.", true);
        btn.disabled  = false;
        btn.innerText = 'Run Scan';
    }
}

function startStatusPolling(btn) {
    if (scanPoller) clearInterval(scanPoller);

    scanPoller = setInterval(async () => {
        try {
            const res  = await fetch('/api/status');
            const data = await res.json();

            if (data.status === 'done') {
                clearInterval(scanPoller);
                scanPoller = null;
                btn.disabled  = false;
                btn.innerText = 'Run Scan';
                showToast("✅ Scan complete! Refreshing report...");
                setTimeout(fetchReport, 800);   // small delay to ensure file is written
            } else if (data.status === 'error') {
                clearInterval(scanPoller);
                scanPoller = null;
                btn.disabled  = false;
                btn.innerText = 'Run Scan';
                showToast(`❌ Scan failed: ${data.error || 'Unknown error'}`, true);
            }
            // While 'running', keep polling silently
        } catch (e) {
            // Network hiccup — just keep polling
        }
    }, 2500);
}

// ── Empty State ───────────────────────────────────────────────────────────────

function renderEmptyState(message) {
    document.getElementById('totalFindings').innerText  = '0';
    document.getElementById('investigateCount').innerText = '0';
    document.getElementById('approveCount').innerText   = '0';
    document.getElementById('autoCount').innerText      = '0';
    document.getElementById('lastScanTime').innerText   = 'Never';

    const manualList = document.getElementById('manualReviewList');
    const autoList   = document.getElementById('autoReviewList');

    manualList.innerHTML = `<div style="color:var(--text-secondary); font-size:0.9rem; padding:16px;">${message}</div>`;
    autoList.innerHTML   = '';
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatDate(isoString) {
    if (!isoString || isoString === '--') return '--';
    try {
        const d = new Date(isoString);
        return d.toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' });
    } catch { return isoString; }
}

function resourceTypeLabel(resourceType) {
    const map = {
        'AWS::S3::Bucket':          'S3 Bucket',
        'AWS::EC2::SecurityGroup':  'EC2 Security Group',
        'AWS::IAM::User':           'IAM User',
        'AWS::RDS::DBInstance':     'RDS Instance',
        'AWS::EBS::Volume':         'EBS Volume',
    };
    return map[resourceType] || resourceType || 'AWS Resource';
}

// ── Render ────────────────────────────────────────────────────────────────────

function renderDashboard() {
    if (!dashboardData) return;

    // Show CURRENT scan count as the headline KPI.
    // current_scan_findings is injected by server.py based on the report timestamp.
    // total_findings includes historical audit-trail merges and is shown as a subtitle.
    const currentCount = dashboardData.current_scan_findings ?? dashboardData.total_findings ?? 0;
    const totalCount   = dashboardData.total_findings ?? 0;
    document.getElementById('totalFindings').innerText  = currentCount;
    const subEl = document.getElementById('totalFindingsHistory');
    if (subEl && totalCount > currentCount) {
        subEl.innerText = `(${totalCount} incl. history)`;
        subEl.style.display = 'block';
    } else if (subEl) {
        subEl.style.display = 'none';
    }
    document.getElementById('lastScanTime').innerText   = formatDate(dashboardData.generated_at);

    let autoCount = 0, approveCount = 0, investigateCount = 0;

    const manualList = document.getElementById('manualReviewList');
    const autoList   = document.getElementById('autoReviewList');
    manualList.innerHTML = '';
    autoList.innerHTML   = '';

    let findings = (dashboardData.findings || []).slice();

    // ── Sort: Recent findings & highest risk scores appear at the top ──
    findings.sort((a, b) => {
        const timeA = Date.parse(a.recorded_at || a.processed_at || dashboardData.generated_at || 0);
        const timeB = Date.parse(b.recorded_at || b.processed_at || dashboardData.generated_at || 0);
        if (timeB !== timeA) return timeB - timeA; // Newest scan timestamp at top
        const scoreA = a.risk?.risk_pct ?? 0;
        const scoreB = b.risk?.risk_pct ?? 0;
        return scoreB - scoreA; // Highest risk score at top
    });

    if (findings.length === 0) {
        manualList.innerHTML = `<div style="color:var(--text-secondary); font-size:0.9rem; padding:16px;">✅ No violations found. Environment is compliant.</div>`;
    }

    findings.forEach(finding => {
        const priority = finding.escalation_priority;

        if (priority === 'quick_approve') {
            approveCount++;
            manualList.appendChild(createCard(finding, 'quick_approve'));
        } else if (priority === 'investigate') {
            investigateCount++;
            manualList.appendChild(createCard(finding, 'investigate'));
        } else {
            autoCount++;
            autoList.appendChild(createCard(finding, 'auto'));
        }
    });

    document.getElementById('investigateCount').innerText = investigateCount;
    document.getElementById('approveCount').innerText     = approveCount;
    document.getElementById('autoCount').innerText        = autoCount;
}

// ── Card Builder ──────────────────────────────────────────────────────────────

function createCard(finding, priorityString) {
    const div   = document.createElement('div');
    div.className = 'ticket-card';
    const uniqueId = finding.finding_id || (finding.control_id + '_' + finding.resource_id + '_' + (finding.recorded_at || finding.processed_at || ''));
    div.id = 'card-' + uniqueId.replace(/[^a-zA-Z0-9]/g, '_');
    div.onclick = () => openModal(finding, priorityString);

    const level      = (finding.risk?.risk_level || 'low').toLowerCase();
    const pct        = finding.risk?.risk_pct ?? 0;
    const confidence = finding.risk?.confidence || {};
    const confBand   = confidence.band || 'HIGH';
    const confScore  = confidence.score ?? 100;
    const scanTimeStr = formatDate(finding.recorded_at || finding.processed_at || dashboardData.generated_at);

    let priorityMarkup = '';
    if (finding.status === 'EXCEPTED') {
        priorityMarkup = `<span class="priority-pill" style="background:rgba(148,163,184,0.15); color:#94a3b8; border:1px solid rgba(148,163,184,0.3);">🛡️ Excepted</span>`;
    } else if (priorityString === 'quick_approve' || finding.status === 'PENDING_APPROVAL') {
        priorityMarkup = `<span class="priority-pill quick_approve">⚡ Pending Approval</span>`;
    } else if (priorityString === 'investigate') {
        priorityMarkup = `<span class="priority-pill investigate">🚨 Investigate</span>`;
    } else {
        priorityMarkup = `<span class="priority-pill auto">🤖 Auto-Remediated</span>`;
    }

    // Data quality warnings — shown inline when inputs were assumed, not confirmed
    const warnings     = confidence.warnings || [];
    const hasWarnings  = warnings.length > 0;
    let confidenceMarkup = '';
    if (hasWarnings) {
        const warningText = warnings.map(w => `<li style="margin:2px 0;">${w}</li>`).join('');
        confidenceMarkup = `<div class="conf-badge conf-medium" style="display:block; margin-top:6px; padding:6px 10px; border-radius:6px;">
            <span style="font-weight:600;">⚠️ Assumed inputs — score may be over-estimated:</span>
            <ul style="margin:4px 0 0 12px; padding:0; font-size:0.8rem; color:#fbbf24;">${warningText}</ul>
        </div>`;
    }

    // Confidence override indicator
    const overrideBanner = finding.confidence_override
        ? `<div class="conf-override-banner">🔒 Context incomplete — overridden to human review</div>`
        : '';

    div.innerHTML = `
        ${overrideBanner}
        <div class="ticket-header">
            <div>
                <h4>${finding.control_name || finding.control_id}</h4>
                <div class="ticket-resource">${finding.resource_id}</div>
                <div style="display:flex; gap:6px; align-items:center; flex-wrap:wrap; margin-top:4px;">
                    <span class="resource-chip">${resourceTypeLabel(finding.resource_type)}</span>
                    <span class="scan-time-chip">🕒 Scanned: ${scanTimeStr}</span>
                </div>
            </div>
            <span class="badge ${level}">${finding.risk?.risk_level || 'N/A'}</span>
        </div>
        <div class="score-bar-wrapper">
            <div class="score-bar-label">
                <span>Operational Risk Score</span>
                <span>${pct}%</span>
            </div>
            <div class="score-bar-track">
                <div class="score-bar-fill ${level}" style="width: ${pct}%;"></div>
            </div>
        </div>
        ${priorityMarkup}
        ${confidenceMarkup}
    `;
    return div;
}

// ── Modal ─────────────────────────────────────────────────────────────────────

function openModal(finding, priorityString) {
    const modal    = document.getElementById('rcaModal');
    const body     = document.getElementById('modalBody');
    const footer   = document.getElementById('modalFooter');
    const subtitle = document.getElementById('modalSubtitle');

    const ctrlId = finding.control_id || (finding.details && finding.details.control_id) || 'CIS Control';
    subtitle.innerText = `${ctrlId}  ·  ${resourceTypeLabel(finding.resource_type)}`;

    const level      = (finding.risk?.risk_level || 'low').toLowerCase();
    const pct        = finding.risk?.risk_pct ?? 0;
    const confidence = finding.risk?.confidence || {};
    const confBand   = confidence.band || 'HIGH';
    const confScore  = confidence.score ?? 100;

    // Data quality warnings panel — replaces the 100-point score display
    const warnings    = confidence.warnings || [];
    const hasWarnings = warnings.length > 0;
    let confPanel = '';
    if (hasWarnings) {
        const warningRows = warnings.map(w =>
            `<div style="display:flex; gap:8px; align-items:flex-start; margin:4px 0; font-size:0.83rem; color:#fbbf24;">
                <span style="flex-shrink:0;">⚠️</span><span>${w}</span>
            </div>`
        ).join('');
        confPanel = `
        <div style="background:rgba(251,191,36,0.07); border:1px solid rgba(251,191,36,0.3);
                    border-radius:8px; padding:12px; margin-bottom:16px;">
            <div style="font-weight:600; font-size:0.85rem; color:#fbbf24; margin-bottom:8px;">
                ⚠️ Data Quality Warnings — Score Based on Partial Assumptions
            </div>
            ${warningRows}
            <div style="margin-top:8px; font-size:0.78rem; color:#aaa; font-style:italic;">
                These tags were not found on the resource. The risk score used conservative defaults.
                Adding the missing tags will improve scoring accuracy.
            </div>
        </div>`;
    }

    const scanTimeStr = formatDate(finding.recorded_at || dashboardData.generated_at);

    let content = `
        ${confPanel}
        <div class="modal-meta-row">
            <div class="modal-meta-item">
                <span class="modal-meta-label">Resource</span>
                <span class="modal-meta-value mono">${finding.resource_id}</span>
            </div>
            <div class="modal-meta-item">
                <span class="modal-meta-label">Region</span>
                <span class="modal-meta-value">${finding.region || 'us-east-1'}</span>
            </div>
            <div class="modal-meta-item">
                <span class="modal-meta-label">Scan Executed</span>
                <span class="modal-meta-value">🕒 ${scanTimeStr}</span>
            </div>
            <div class="modal-meta-item">
                <span class="modal-meta-label">Operational Risk Score</span>
                <span class="modal-meta-value">${pct}%&nbsp;<span class="badge ${level}">${finding.risk?.risk_level || ''}</span></span>
            </div>
        </div>
        <div class="score-bar-wrapper" style="margin-bottom:20px;">
            <div class="score-bar-track" style="height:7px;">
                <div class="score-bar-fill ${level}" style="width: ${pct}%;"></div>
            </div>
        </div>
    `;

    if (finding.risk?.rationale) {
        content += `<p style="font-style:italic; margin-bottom:4px;">${finding.risk.rationale}</p>`;
    }

    if (finding.llm_analysis) {
        const a = finding.llm_analysis;

        // Gate banner — use gate_reason (always set for PROCEED & BLOCK) with backward-compat fallback
        const gateReason = finding.gate_reason || a.gate_reason ||
                           finding.gate_block_reason || a.gate_block_reason;
        let gateBanner = '';
        if (gateReason) {
            // gate_action is the authoritative PROCEED/BLOCK flag from the Safety Gate
            let isProceed = false;
            if (finding.gate_action) {
                isProceed = (finding.gate_action.toUpperCase() === 'PROCEED');
            } else {
                // Legacy fallback for older reports without gate_action
                const reasonUpper = gateReason.toUpperCase();
                const isBlock = reasonUpper.includes('LOCKOUT') || 
                                reasonUpper.includes('BLOCKED') || 
                                reasonUpper.includes('BASTION') || 
                                reasonUpper.includes('DISCONNECTION') || 
                                reasonUpper.includes('MUST SUPPLY') || 
                                reasonUpper.includes('MUST REVIEW') || 
                                reasonUpper.includes('HUMAN');
                isProceed = !isBlock && (reasonUpper.includes('PROCEED') || reasonUpper.includes('SAFE TO'));
            }
            
            if (isProceed) {
                 gateBanner = `<div style="background:rgba(16,185,129,0.1); border-left:3px solid #10b981;
                 padding:10px 12px; border-radius:6px; margin-bottom:14px;">
                 <strong style="color:#10b981;">✅ Remediation Safety Gate — PROCEED</strong>
                 <p style="margin:4px 0 0; color:#10b981; font-size:0.85rem;">${gateReason}</p>
                </div>`;
            } else {
                 gateBanner = `<div style="background:rgba(239,68,68,0.1); border-left:3px solid #f87171;
                 padding:10px 12px; border-radius:6px; margin-bottom:14px;">
                 <strong style="color:#f87171;">⛔ Remediation Safety Gate — BLOCKED</strong>
                 <p style="margin:4px 0 0; color:#f87171; font-size:0.85rem;">${gateReason}</p>
                </div>`;
            }
        }

        const toArray = (val) => {
            if (Array.isArray(val)) return val;
            if (typeof val === 'string' && val.trim()) return [val.trim()];
            return [];
        };

        const fixSteps = toArray(a.fix_steps);
        const prereqs = toArray(a.prerequisite_actions);
        const rollbackSteps = toArray(a.rollback_steps);

        // fix_steps as numbered list
        const fixStepsHtml = fixSteps.length
            ? `<ol style="padding-left:18px; margin:6px 0 0;">
                ${fixSteps.map(s => `<li style="margin:4px 0; font-size:0.88rem;">${s}</li>`).join('')}
               </ol>`
            : '';

        // prerequisite_actions as warning block
        const validPrereqs = prereqs.filter(s => 
            s && 
            !s.includes('What must be done BEFORE') && 
            !s.toLowerCase().startsWith('none')
        );

        const prereqsHtml = validPrereqs.length
            ? `<div style="background:rgba(249,115,22,0.08); border:1px solid rgba(249,115,22,0.3);
                border-radius:6px; padding:10px 12px; margin-top:10px;">
                <strong style="color:#fb923c; font-size:0.85rem;">⚠ Prerequisites before remediation:</strong>
                <ol style="padding-left:18px; margin:6px 0 0;">
                  ${validPrereqs.map(s => `<li style="margin:4px 0; font-size:0.85rem; color:#fb923c;">${s}</li>`).join('')}
                </ol>
               </div>`
            : '';

        // rollback_steps
        const rollbackHtml = rollbackSteps.length
            ? `<hr class="modal-divider">
               <h4>↩ Rollback Plan</h4>
               <ol style="padding-left:18px; margin:6px 0 0;">
                 ${rollbackSteps.map(s => `<li style="margin:4px 0; font-size:0.88rem;">${s}</li>`).join('')}
               </ol>`
            : '';

        let manualPlanHtml = '';
        if (!finding.auto_remediation || finding.auto_remediation.status !== 'success') {
            manualPlanHtml = `
            <h4>Recommended Fix</h4>
            <p style="color: #fff; font-weight:500;">${a.recommended_fix || 'N/A'}</p>
            ${fixStepsHtml}
            ${prereqsHtml}
            <h4>Operational Impact</h4>
            <p>${a.operational_impact || 'N/A'}</p>
            <h4>Safe Window</h4>
            <p>${a.safe_window || 'N/A'}</p>
            ${rollbackHtml}
            `;
        }

        content += `
            <hr class="modal-divider">
            ${gateBanner}
            <h4>🧠 Root Cause Analysis (RCA)</h4>
            <p>${a.root_cause || 'N/A'}</p>
            <h4>Business Impact</h4>
            <p>${a.business_impact || 'N/A'}</p>
            ${manualPlanHtml}
        `;
    }

    if (finding.auto_remediation) {
        const r = finding.auto_remediation;
        const ps = r.pre_remediation_state;
        content += `
            <hr class="modal-divider">
            <h4>🤖 Auto-Remediation Execution Log</h4>
            <p><strong style="color:#fff;">Status:</strong> ${r.status}</p>
            <p><strong style="color:#fff;">Message:</strong> ${r.message}</p>
            ${ps ? `<div style="background:rgba(255,255,255,0.04); border:1px solid #333; border-radius:6px; padding:10px; margin-top:10px;">
                <span style="font-size:0.8rem; color:#aaa;">📦 Pre-Remediation Snapshot captured at ${ps.captured_at || 'N/A'}</span><br>
                <span style="font-size:0.8rem; color:#aaa;">↩ Restore call: <code>${ps.restore_call || 'manual'}</code></span>
            </div>` : ''}
        `;
    }

    // Check for active exception on this finding
    if (finding.status === 'EXCEPTED' || finding.exception) {
        const exc = finding.exception || {};
        content += `
            <hr class="modal-divider">
            <div style="background:rgba(148,163,184,0.08); border-left:3px solid #94a3b8; padding:12px 14px; border-radius:6px; margin-bottom:14px;">
                 <strong style="color:#94a3b8; font-size:0.95rem;">🛡️ Formally Approved Compliance Exception Active</strong>
                 <p style="margin:6px 0 2px; color:#e2e8f0; font-size:0.88rem;"><strong>Justification:</strong> "${exc.justification || finding.auto_remediation?.message || 'Approved business exemption'}"</p>
                 <p style="margin:2px 0 0; color:#94a3b8; font-size:0.8rem;">
                     Owner: <code>${exc.business_owner || 'secops@company.com'}</code> &nbsp;·&nbsp;
                     Approved By: <code>${exc.approved_by || 'ciso@company.com'}</code> &nbsp;·&nbsp;
                     Expires: <strong>${exc.expiry_date || 'Active'}</strong>
                 </p>
            </div>
        `;
    }

    if (!finding.llm_analysis && !finding.auto_remediation && finding.status !== 'EXCEPTED') {
        content += `
            <hr class="modal-divider">
            <div style="background:rgba(16,185,129,0.08); border-left:3px solid #10b981; padding:10px 12px; border-radius:6px; margin-bottom:14px;">
                 <strong style="color:#10b981;">🤖 Autonomous Safety Gate &amp; Remediation Log</strong>
                 <p style="margin:4px 0 0; color:#aaa; font-size:0.85rem;">This violation was processed by ComplianceGuard's decision orchestrator and remediated natively via AWS APIs.</p>
            </div>
            <h4>🧠 Violation Details &amp; Diagnosis</h4>
            <p>${finding.details?.violation || finding.details?.remediation_note || 'Deterministic policy scoring verified zero active workload dependency.'}</p>
        `;
    }

    body.innerHTML = content;

    const uniqueId = finding.finding_id || (finding.control_id + '_' + finding.resource_id + '_' + (finding.recorded_at || finding.processed_at || ''));
    const cardDomId = 'card-' + uniqueId.replace(/[^a-zA-Z0-9]/g, '_');

    // Modal Footer Buttons
    footer.innerHTML = '';

    const cancelBtn = document.createElement('button');
    cancelBtn.className = 'btn btn-secondary';
    cancelBtn.textContent = 'Cancel';
    cancelBtn.onclick = closeModal;
    footer.appendChild(cancelBtn);

    const excBtn = document.createElement('button');
    excBtn.className = 'btn btn-secondary';
    excBtn.style.border = '1px solid rgba(148,163,184,0.3)';
    excBtn.style.color = '#94a3b8';
    excBtn.textContent = '🛡️ Grant Exception';
    excBtn.onclick = () => {
        closeModal();
        openGrantExceptionModal(finding.resource_id, finding.control_id, finding.finding_id);
    };
    footer.appendChild(excBtn);

    if (priorityString === 'quick_approve' || finding.status === 'PENDING_APPROVAL') {
        const denyBtn = document.createElement('button');
        denyBtn.className = 'btn btn-investigate';
        denyBtn.textContent = '✘ Deny';
        denyBtn.style.marginLeft = 'auto';
        denyBtn.onclick = () => denyFinding(finding.finding_id, cardDomId);

        const approveBtn = document.createElement('button');
        approveBtn.className = 'btn btn-approve';
        approveBtn.textContent = '✔ Approve & Remediate';
        approveBtn.onclick = () => approveAndMove(finding.resource_id, finding.control_name, cardDomId, finding);

        footer.appendChild(denyBtn);
        footer.appendChild(approveBtn);
    } else if (priorityString === 'investigate') {
        const escBtn = document.createElement('button');
        escBtn.className = 'btn btn-investigate';
        escBtn.style.marginLeft = 'auto';
        escBtn.textContent = 'Escalate to Engineering';
        escBtn.onclick = () => mockAction(`Escalated ${finding.resource_id} to Engineering`);

        const forceBtn = document.createElement('button');
        forceBtn.className = 'btn btn-primary';
        forceBtn.textContent = 'Force Apply Fix';
        forceBtn.onclick = () => mockAction(`Force-applied fix for ${finding.resource_id}`);

        footer.appendChild(escBtn);
        footer.appendChild(forceBtn);
    }

    // Rollback button for remediated findings
    const isRemediated = (
        finding.auto_remediation &&
        (finding.auto_remediation.status === 'success' ||
         finding.auto_remediation.status === 'COMPLIANT' ||
         finding.status === 'COMPLIANT' ||
         finding.status === 'AUTO_REMEDIATED')
    );

    if (isRemediated && finding.status !== 'ROLLED_BACK' && finding.auto_remediation?.status !== 'ROLLED_BACK') {
        const rollbackBtn = document.createElement('button');
        rollbackBtn.className = 'btn btn-rollback';
        rollbackBtn.style.marginLeft = 'auto';
        rollbackBtn.innerHTML = '↩ Rollback Remediation';
        rollbackBtn.onclick = () => rollbackRemediation(finding, cardDomId);
        footer.appendChild(rollbackBtn);
    }


    modal.classList.add('active');
}

function handleOverlayClick(e) {
    if (e.target === document.getElementById('rcaModal')) closeModal();
}

function closeModal() {
    document.getElementById('rcaModal').classList.remove('active');
}

// ── Live Approve-and-Move ─────────────────────────────────────────────────────

async function approveAndMove(resourceId, controlName, cardDomId, finding) {
    const card = cardDomId ? document.getElementById(cardDomId) : document.getElementById('card-' + resourceId.replace(/[^a-zA-Z0-9]/g, '_'));

    // Change button text in modal to show loading state
    const btn = document.querySelector('.btn-approve');
    if (btn) {
        btn.innerText = 'Remediating...';
        btn.disabled = true;
    }

    try {
        const response = await fetch('/api/approve', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                finding_id:  finding ? finding.finding_id : null,
                resource_id: resourceId,
                approved_by: 'dashboard-admin',
            })
        });
        
        const data = await response.json();
        
        if (!response.ok || !data.success) {
            throw new Error(data.message || data.error || 'Remediation failed');
        }

        // Show verified_at and observed state in success card
        const verifiedAt  = data.verified_at ? new Date(data.verified_at).toLocaleTimeString() : '';
        const observedStr = data.observed_state ? JSON.stringify(data.observed_state) : '';
        closeModal();
        const autoList = document.getElementById('autoReviewList');
        card.classList.add('card-removing');

        setTimeout(() => {
            card.remove();

            const doneCard = document.createElement('div');
            doneCard.className = 'ticket-card';
            doneCard.style.borderLeft = '3px solid var(--low)';
            const findingControlId = (finding && finding.control_id) ? finding.control_id : (controlName && controlName.startsWith('CIS') ? controlName.split(' ')[0] : 'CIS-5.2');
            const findingResType = (finding && finding.resource_type) ? finding.resource_type : 'AWS::EC2::SecurityGroup';
            const findingPreState = data.pre_remediation_state || (finding?.auto_remediation?.pre_remediation_state);
            const findingId = finding ? finding.finding_id : null;

            doneCard.onclick = () => openModal({
                finding_id: findingId,
                control_id: findingControlId,
                resource_id: resourceId,
                control_name: controlName || finding?.control_name || findingControlId,
                resource_type: findingResType,
                region: finding?.region || 'us-east-1',
                recorded_at: finding?.recorded_at,
                risk: { risk_level: 'LOW', risk_pct: 0 },
                status: 'COMPLIANT',
                auto_remediation: {
                    status: 'success',
                    message: data.message,
                    pre_remediation_state: findingPreState
                }
            }, 'auto');
            doneCard.innerHTML = `
                <div class="ticket-header">
                    <div>
                        <h4>${controlName}</h4>
                        <div class="ticket-resource">${resourceId}</div>
                        ${verifiedAt ? `<div style="font-size:0.75rem;color:#10b981;margin-top:3px;">✅ Verified compliant at ${verifiedAt}</div>` : ''}
                    </div>
                    <span class="badge low">COMPLIANT</span>
                </div>
                <div class="score-bar-wrapper">
                    <div class="score-bar-label"><span>Status</span><span>✅ Applied natively in AWS</span></div>
                </div>
                <div style="margin-top:10px; font-size:0.8rem; color:#aaa;">${data.message}</div>
                <span class="priority-pill auto">🤖 Auto-Remediated</span>
            `;
            autoList.prepend(doneCard);

            const prev     = parseInt(document.getElementById('approveCount').innerText) || 0;
            const prevAuto = parseInt(document.getElementById('autoCount').innerText)    || 0;
            document.getElementById('approveCount').innerText = Math.max(0, prev - 1);
            document.getElementById('autoCount').innerText    = prevAuto + 1;

            showToast(`✅ Fix successfully applied to AWS for ${resourceId}`);
        }, 500);

    } catch (err) {
        console.error(err);
        showToast(`❌ Failed: ${err.message}`, true);
        if (btn) {
            btn.innerText = '✔ Approve & Remediate';
            btn.disabled = false;
        }
    }
}

// ── Rollback Remediation ──────────────────────────────────────────────────────

async function rollbackRemediation(finding, cardDomId) {
    const resourceId = finding.resource_id;
    const confirmMsg = `Are you sure you want to rollback the remediation for ${resourceId}?\n\nThis will restore its original pre-remediation configuration in AWS.`;
    if (!confirm(confirmMsg)) return;

    const btn = document.querySelector('.btn-rollback');
    if (btn) {
        btn.innerText = 'Rolling back...';
        btn.disabled = true;
    }

    try {
        const response = await fetch('/api/rollback', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                finding_id:  finding.finding_id || null,
                resource_id: resourceId,
                control_id:  finding.control_id || null,
                rolled_back_by: 'dashboard-admin',
            })
        });

        const data = await response.json();
        if (!response.ok || !data.success) {
            throw new Error(data.error || data.message || 'Rollback failed');
        }

        showToast(`↩ Successfully rolled back ${resourceId}`);
        closeModal();

        // Refresh dashboard data to reflect current AWS and report state
        setTimeout(fetchReport, 800);
    } catch (e) {
        showToast(`❌ Rollback failed: ${e.message}`, true);
        if (btn) {
            btn.innerText = '↩ Rollback Remediation';
            btn.disabled = false;
        }
    }
}

// ── Deny Finding ──────────────────────────────────────────────────────────────

async function denyFinding(findingId, cardDomId) {
    if (!findingId) {
        showToast('❌ No finding ID — cannot deny.', true);
        return;
    }
    closeModal();
    try {
        const res = await fetch('/api/deny', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                finding_id: findingId,
                denied_by:  'dashboard-admin',
                reason:     'Denied by administrator via dashboard.',
            }),
        });
        const data = await res.json();
        if (!res.ok || !data.success) throw new Error(data.error || 'Deny failed');

        // Mark the card visually as denied
        const card = cardDomId ? document.getElementById(cardDomId) : null;
        if (card) {
            card.style.opacity   = '0.45';
            card.style.borderLeft = '3px solid #6b7280';
            const header = card.querySelector('.ticket-header > div > h4');
            if (header) header.style.textDecoration = 'line-through';
            const badge = card.querySelector('.badge');
            if (badge) { badge.className = 'badge'; badge.textContent = 'DENIED'; }
        }
        showToast('✘ Finding denied — no action will be taken.');
    } catch (err) {
        showToast(`❌ Deny failed: ${err.message}`, true);
    }
}

// ── Mock Actions ──────────────────────────────────────────────────────────────

function mockAction(message) {
    closeModal();
    showToast(message);
}


function showToast(msg, isError = false) {
    const toast = document.getElementById('toast');
    toast.innerText    = msg;
    toast.style.borderLeft = isError ? '4px solid var(--critical)' : '4px solid var(--accent-primary)';
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 3500);
}

// ── View Switching & History ───────────────────────────────────────────────────

let historyData = [];

function switchView(viewName, el) {
    // Update nav active state
    document.querySelectorAll('.nav-menu .nav-item').forEach(item => item.classList.remove('active'));
    if (el) el.classList.add('active');

    // Toggle view visibility
    document.querySelectorAll('.page-view').forEach(v => v.style.display = 'none');
    const target = document.getElementById('view-' + viewName);
    if (target) {
        target.style.display = 'block';
    }

    if (viewName === 'history') {
        loadHistoryView();
    } else if (viewName === 'exceptions') {
        loadExceptionsView();
    }
}

async function loadHistoryView() {
    try {
        const res = await fetch('/api/history');
        if (res.ok) {
            const data = await res.json();
            if (Array.isArray(data) && data.length > 0) {
                historyData = data;
            } else if (dashboardData && dashboardData.findings) {
                // Synthesize history entries from current scan report
                historyData = dashboardData.findings.map((f, idx) => ({
                    audit_id: f.finding_id || `AUDIT-${idx}`,
                    timestamp: f.recorded_at || f.processed_at || dashboardData.generated_at,
                    control_id: f.control_id,
                    resource_id: f.resource_id,
                    resource_type: f.resource_type,
                    risk_pct: f.risk?.risk_pct ?? 0,
                    risk_level: f.risk?.risk_level ?? 'N/A',
                    action_taken: f.escalation_priority === 'investigate' ? 'BLOCKED' :
                                  f.escalation_priority === 'quick_approve' ? 'LLM_ESCALATION' : 'AUTO_REMEDIATION_SUCCESS',
                    compliance_status: f.auto_remediation?.status === 'success' ? 'REMEDIATED' : 'NON_COMPLIANT'
                }));
            }
        }
    } catch (e) {
        console.error("Failed to load history:", e);
    }
    renderHistoryTable();
}

function renderHistoryTable() {
    const tbody = document.getElementById('historyTableBody');
    const filter = document.getElementById('historyFilter')?.value || 'ALL';
    const countEl = document.getElementById('historyCount');
    if (!tbody) return;

    tbody.innerHTML = '';
    
    let list = historyData.slice();
    if (filter !== 'ALL') {
        list = list.filter(item => {
            if (filter === 'BLOCKED') return item.action_taken === 'BLOCKED' || (item.gate_block_reason || '').length > 0;
            return item.action_taken === filter;
        });
    }

    if (countEl) countEl.innerText = `Showing ${list.length} of ${historyData.length} entries`;

    if (list.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-secondary); padding:24px;">No audit log records found for this filter.</td></tr>`;
        return;
    }

    list.forEach(item => {
        const tr = document.createElement('tr');
        const level = (item.risk_level || 'low').toLowerCase();
        
        let actionBadge = '';
        if (item.action_taken === 'AUTO_REMEDIATION_SUCCESS' || item.action_taken === 'AUTO') {
            actionBadge = `<span class="priority-pill auto" style="margin:0;">🤖 Auto-Remediated</span>`;
        } else if (item.action_taken === 'BLOCKED') {
            actionBadge = `<span class="priority-pill investigate" style="margin:0;">⛔ Gate Blocked</span>`;
        } else {
            actionBadge = `<span class="priority-pill quick_approve" style="margin:0;">⚡ Escalated/Approved</span>`;
        }

        tr.innerHTML = `
            <td style="font-size:0.83rem; color:var(--text-secondary); white-space:nowrap;">${formatDate(item.timestamp)}</td>
            <td style="font-family:'Space Mono', monospace; font-size:0.85rem; color:var(--accent-primary); font-weight:600;">${item.control_id}</td>
            <td style="font-family:'Space Mono', monospace; font-size:0.83rem; color:var(--text-mono);">${item.resource_id}</td>
            <td style="font-size:0.8rem; color:var(--text-secondary);">${resourceTypeLabel(item.resource_type)}</td>
            <td><span class="badge ${level}">${item.risk_pct != null ? item.risk_pct + '%' : ''} ${item.risk_level || ''}</span></td>
            <td>${actionBadge}</td>
            <td style="font-size:0.83rem; font-weight:600; color:${item.compliance_status === 'REMEDIATED' ? 'var(--low)' : 'var(--high)'}">${item.compliance_status || 'PROCESSED'}</td>
        `;
        tbody.appendChild(tr);
    });
}

// ── Policy Matrix Overhaul Interactive Filtering ─────────────────────────────

let activePolicyCategory = 'ALL';

function filterPolicies(category) {
    activePolicyCategory = category;
    
    // Update active tab UI
    document.querySelectorAll('.cat-tab').forEach(tab => {
        if (tab.getAttribute('data-category') === category) {
            tab.classList.add('active');
        } else {
            tab.classList.remove('active');
        }
    });

    searchPolicies();
}

function searchPolicies() {
    const query = (document.getElementById('policySearchInput')?.value || '').toLowerCase();
    const actionFilter = document.getElementById('policyActionFilter')?.value || 'ALL';
    
    const cards = document.querySelectorAll('.matrix-card');
    
    cards.forEach(card => {
        const cat = card.getAttribute('data-category');
        const ruleId = (card.getAttribute('data-rule-id') || '').toLowerCase();
        const actions = card.getAttribute('data-actions') || '';
        const cardText = card.innerText.toLowerCase();

        // Check Category Match
        const matchCategory = (activePolicyCategory === 'ALL' || cat === activePolicyCategory);
        
        // Check Search Query Match
        const matchQuery = !query || ruleId.includes(query) || cardText.includes(query);
        
        // Check Action Filter Match
        const matchAction = (actionFilter === 'ALL' || actions.includes(actionFilter));

        if (matchCategory && matchQuery && matchAction) {
            card.style.display = 'block';
            card.style.animation = 'fadeIn 0.3s ease-out';
        } else {
            card.style.display = 'none';
        }
    });
}

// ── Exception Management & Governance ────────────────────────────────────────

let exceptionsData = [];

async function loadExceptionsView() {
    try {
        const res = await fetch('/api/exceptions');
        if (res.ok) {
            exceptionsData = await res.json();
        } else {
            exceptionsData = [];
        }
    } catch (e) {
        console.error("Failed to load exceptions:", e);
        exceptionsData = [];
    }
    renderExceptionsOverview();
    renderExceptionsTable();
}

function renderExceptionsOverview() {
    const totalEl   = document.getElementById('totalExceptionsCount');
    const activeEl  = document.getElementById('activeExceptionsCount');
    const expiredEl = document.getElementById('expiredExceptionsCount');
    const revokedEl = document.getElementById('revokedExceptionsCount');

    let active = 0, expired = 0, revoked = 0;
    exceptionsData.forEach(exc => {
        const status = (exc.status || 'active').toLowerCase();
        if (status === 'active') active++;
        else if (status === 'expired') expired++;
        else if (status === 'revoked') revoked++;
    });

    if (totalEl) totalEl.innerText = exceptionsData.length;
    if (activeEl) activeEl.innerText = active;
    if (expiredEl) expiredEl.innerText = expired;
    if (revokedEl) revokedEl.innerText = revoked;
}

function renderExceptionsTable() {
    const tbody = document.getElementById('exceptionsTableBody');
    const statusFilter = document.getElementById('exceptionStatusFilter')?.value || 'ALL';
    const searchQuery = (document.getElementById('exceptionSearchInput')?.value || '').toLowerCase();
    const countLabel = document.getElementById('exceptionCountLabel');
    if (!tbody) return;

    tbody.innerHTML = '';

    let list = exceptionsData.slice();

    if (statusFilter !== 'ALL') {
        list = list.filter(item => (item.status || 'active').toLowerCase() === statusFilter.toLowerCase());
    }

    if (searchQuery) {
        list = list.filter(item => {
            const combined = `${item.exception_id || ''} ${item.resource_id || ''} ${item.control_id || ''} ${item.justification || ''} ${item.approved_by || ''}`.toLowerCase();
            return combined.includes(searchQuery);
        });
    }

    if (countLabel) countLabel.innerText = `Showing ${list.length} of ${exceptionsData.length} waivers`;

    if (list.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-secondary); padding:28px;">No compliance waivers found matching your criteria.</td></tr>`;
        return;
    }

    list.forEach(exc => {
        const tr = document.createElement('tr');
        const status = (exc.status || 'active').toLowerCase();

        let statusBadge = '';
        if (status === 'active') {
            statusBadge = `<span class="badge low" style="padding:4px 10px; font-size:0.75rem;">🟢 ACTIVE</span>`;
        } else if (status === 'expired') {
            statusBadge = `<span class="badge high" style="padding:4px 10px; font-size:0.75rem;">⏳ EXPIRED</span>`;
        } else {
            statusBadge = `<span class="badge" style="padding:4px 10px; font-size:0.75rem; background:rgba(148,163,184,0.15); color:#94a3b8;">🚫 REVOKED</span>`;
        }

        const actionBtn = (status === 'active')
            ? `<button class="btn btn-investigate" style="padding:4px 10px; font-size:0.75rem;" onclick="revokeException('${exc.exception_id}')">Revoke</button>`
            : `<span style="font-size:0.8rem; color:var(--text-secondary);">--</span>`;

        tr.innerHTML = `
            <td class="mono" style="font-size:0.82rem; color:var(--accent-primary); font-weight:600;">${exc.exception_id || 'N/A'}</td>
            <td>
                <div style="font-weight:600; color:#fff; font-size:0.88rem;">${exc.control_id}</div>
                <div class="mono" style="font-size:0.78rem; color:var(--text-secondary); margin-top:2px;">${exc.resource_id}</div>
            </td>
            <td style="max-width:320px;">
                <div style="font-size:0.85rem; color:#e2e8f0;">"${exc.justification || 'N/A'}"</div>
                <div style="font-size:0.75rem; color:var(--text-secondary); margin-top:3px;">Owner: ${exc.business_owner || 'N/A'}</div>
            </td>
            <td style="font-size:0.83rem; color:var(--text-secondary);">${exc.approved_by || 'admin'}</td>
            <td>
                <div style="font-size:0.85rem; color:#fff; font-weight:500;">${exc.expiry_date || 'N/A'}</div>
                <div style="font-size:0.72rem; color:var(--text-secondary);">Approved: ${exc.approved_date || 'N/A'}</div>
            </td>
            <td>${statusBadge}</td>
            <td>${actionBtn}</td>
        `;
        tbody.appendChild(tr);
    });
}

function openGrantExceptionModal(resourceId = '', controlId = '', findingId = '') {
    const modal = document.getElementById('grantExceptionModal');
    if (!modal) return;

    document.getElementById('excResourceId').value = resourceId || '';
    if (controlId) {
        const select = document.getElementById('excControlId');
        if (select) {
            let found = false;
            for (let opt of select.options) {
                if (opt.value === controlId) {
                    select.value = controlId;
                    found = true;
                    break;
                }
            }
            if (!found && controlId) {
                const newOpt = new Option(controlId, controlId, true, true);
                select.add(newOpt);
            }
        }
    }
    document.getElementById('excFindingId').value = findingId || '';
    document.getElementById('excJustification').value = '';
    setExcDuration(30);

    modal.classList.add('active');
}

function closeGrantExceptionModal() {
    const modal = document.getElementById('grantExceptionModal');
    if (modal) modal.classList.remove('active');
}

function setExcDuration(days, btnElement) {
    document.getElementById('excDays').value = days;
    document.querySelectorAll('.duration-chip').forEach(chip => chip.classList.remove('active'));
    if (btnElement) {
        btnElement.classList.add('active');
    } else {
        document.querySelectorAll('.duration-chip').forEach(chip => {
            if (chip.innerText.startsWith(`${days} `)) chip.classList.add('active');
        });
    }
}

async function submitGrantException(event) {
    event.preventDefault();
    const btn = document.getElementById('excSubmitBtn');
    if (btn) {
        btn.innerText = 'Granting waiver...';
        btn.disabled = true;
    }

    const payload = {
        resource_id:    document.getElementById('excResourceId').value.trim(),
        control_id:     document.getElementById('excControlId').value.trim(),
        justification:  document.getElementById('excJustification').value.trim(),
        business_owner: document.getElementById('excOwner').value.trim(),
        approved_by:    document.getElementById('excApprover').value.trim(),
        days:           parseInt(document.getElementById('excDays').value, 10) || 30,
        finding_id:     document.getElementById('excFindingId').value || null
    };

    try {
        const res = await fetch('/api/exceptions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await res.json();
        if (!res.ok || !data.success) {
            throw new Error(data.error || 'Failed to grant exception');
        }

        closeGrantExceptionModal();
        showToast(`🛡️ Exception ${data.exception?.exception_id || ''} granted until ${data.exception?.expiry_date || ''}!`);

        // Refresh views
        await loadExceptionsView();
        await fetchReport();

    } catch (err) {
        showToast(`❌ Error granting exception: ${err.message}`, true);
    } finally {
        if (btn) {
            btn.innerText = '🛡️ Confirm & Grant Exception';
            btn.disabled = false;
        }
    }
}

async function revokeException(exceptionId) {
    if (!confirm(`Are you sure you want to revoke exception ${exceptionId}? Future scans will treat this resource as a live violation.`)) {
        return;
    }

    try {
        const res = await fetch('/api/exceptions/revoke', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ exception_id: exceptionId })
        });

        const data = await res.json();
        if (!res.ok || !data.success) throw new Error(data.error || 'Revoke failed');

        showToast(`🚫 Exception ${exceptionId} revoked.`);
        await loadExceptionsView();
        await fetchReport();
    } catch (err) {
        showToast(`❌ Failed to revoke exception: ${err.message}`, true);
    }
}

