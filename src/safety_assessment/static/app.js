const root = document.querySelector('#app');
const labels = {created:'待启动',running:'执行中',completed:'已完成',failed:'失败',stopped:'已停止',idle:'待执行',success:'成功',pending:'待验证',static_confirmed:'静态复核命中',needs_review:'需人工复核',critical:'严重',high:'高危',medium:'中危',low:'低危',info:'提示'};
const stages = {environment_scan:'环境准备与检查',code_analysis:'源码安全分析',vulnerability_verify:'危险信号复核',report_generate:'报告整理',done:'评估完成'};
const roles = {general:'通用协调',environment:'环境检查',analyst:'代码分析',verifier:'漏洞验证',reporter:'报告整理',operations:'运维辅助'};
let user = null;
let socket = null;
let refreshTimer = null;
let pollTimer = null;
let generation = 0;
let selectedRisk = '';
let toastTimer;
let importFiles = [];
let importMode = 'upload';
let importBusy = false;
const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g, character => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character]));
const badge = value => `<span class="badge ${escapeHTML(value)}">${escapeHTML(labels[value] || value)}</span>`;
const date = value => {
  if (!value) return '—';
  if (/^\d{4}\/\d{2}\/\d{2}\/\d{2}\.\d{2}$/.test(value)) return value;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return '—';
  const parts = Object.fromEntries(new Intl.DateTimeFormat('en-GB', {timeZone:'Asia/Shanghai',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hourCycle:'h23'}).formatToParts(parsed).map(part => [part.type,part.value]));
  return `${parts.year}/${parts.month}/${parts.day}/${parts.hour}.${parts.minute}`;
};
const empty = text => `<div class="empty">${escapeHTML(text)}</div>`;

async function api(path, options = {}) {
  const response = await fetch('/api' + path, {headers: options.body instanceof FormData ? {} : {'Content-Type':'application/json'}, ...options});
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && !path.includes('/login')) user = null;
    throw new Error(typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail || '请求失败'));
  }
  return data;
}

function toast(message, error = false) {
  const target = document.querySelector('#toast');
  target.textContent = message;
  target.className = error ? 'error' : '';
  target.style.display = 'block';
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => target.style.display = 'none', 5000);
}

function shell(content, active = 'projects') {
  root.innerHTML = `<div class="layout"><aside class="sidebar"><a href="#projects" class="brand">SENTINEL<span>◈</span></a><div class="brand-sub">SOURCE SECURITY PLATFORM</div><nav class="nav"><a class="${active === 'projects' ? 'active' : ''}" href="#projects">▦ &nbsp;评估项目</a><a class="${active === 'examples' ? 'active' : ''}" href="#examples">◈ &nbsp;正反案例</a>${user.role === 'admin' ? `<a class="${active === 'config' ? 'active' : ''}" href="#config">⚙ &nbsp;系统配置</a>` : ''}</nav><div class="side-foot"><span class="dot"></span> &nbsp;确定性静态规则引擎<br>只读分析 · 证据可回溯<br>仅限授权项目安全评估</div><div class="user"><div class="avatar">${escapeHTML(user.username[0].toUpperCase())}</div><div>${escapeHTML(user.username)}<br><small>${user.role === 'admin' ? '系统管理员' : '普通使用者'}</small></div><button data-action="logout" aria-label="退出登录">↗</button></div></aside><main>${content}</main></div>`;
}

async function authPage() {
  const status = await api('/system/status');
  const initializing = !status.initialized;
  root.innerHTML = `<div class="auth-page"><section class="auth-art"><div><div class="brand">SENTINEL<span>◈</span></div><div class="brand-sub">AUTOMATED SECURITY ASSESSMENT</div></div><div><div class="shield">✓</div><h1>让安全风险<br>从源码中显现。</h1><p>从项目接入、源码分析到证据复核与报告，构建可追溯的安全评估工作流。</p></div><div class="status-line"><span class="dot"></span>源码只读接入 / 六类执行角色 / 实时监控</div></section><section class="auth-form"><form id="auth-form" class="auth-box" data-init="${initializing}"><div class="eyebrow">WELCOME TO SENTINEL</div><h1>${initializing ? '初始化安全工作台' : '登录安全工作台'}</h1><p class="muted">${initializing ? '首次使用，请创建管理员账户。' : '使用账户继续管理你的安全评估项目。'}</p><label>用户名<input name="username" required minlength="3" maxlength="80" autocomplete="username" pattern="[a-zA-Z0-9_.\-]+" placeholder="输入用户名"></label><label>密码<input name="password" type="password" required minlength="8" maxlength="128" autocomplete="${initializing ? 'new-password' : 'current-password'}" placeholder="至少 8 位密码"></label><button class="primary">${initializing ? '创建管理员并登录 →' : '登录工作台 →'}</button><p class="help">数据库连接密码与这里的登录密码相互独立。${initializing ? '管理员仅能从本机初始化。' : '登录态使用 HttpOnly Cookie，8 小时有效。'}</p></form></section></div>`;
}

async function projectsPage() {
  const projects = await api('/projects');
  const count = status => projects.filter(project => project.project_status === status).length;
  shell(`<div class="topline"><div><div class="eyebrow">SECURITY / PROJECTS</div><h1>安全评估项目</h1><div class="muted">接入源码，追踪每一次风险发现。</div></div><a href="#new"><button class="primary">＋ 创建评估项目</button></a></div><div class="stats">${[['项目总数',projects.length],['正在评估',count('running')],['已完成',count('completed')],['待启动',count('created')]].map(([title,number]) => `<div class="stat"><small>${title}</small><strong>${number.toString().padStart(2,'0')}</strong></div>`).join('')}</div><div class="panel"><div class="panel-head"><h2>项目工作空间</h2><span class="status-line"><span class="dot"></span>源码安全评估</span></div>${projects.length ? `<div class="table-wrap"><table><thead><tr><th>项目名称</th><th>源码来源</th><th>状态</th><th>最近启动</th><th>最近完成</th><th>操作</th></tr></thead><tbody>${projects.map(project => `<tr><td class="title"><a href="#project/${project.id}">${escapeHTML(project.project_name)}</a><br><small>#${project.id} · ${escapeHTML(project.environment_type)}</small></td><td class="source" title="${escapeHTML(project.source_path)}">${escapeHTML(project.source_path)}</td><td>${badge(project.project_status)}</td><td>${date(project.started_at)}</td><td>${date(project.finished_at)}</td><td><a href="#project/${project.id}">查看 →</a></td></tr>`).join('')}</tbody></table></div>` : empty('还没有评估项目。创建项目，或从正反案例开始。')}</div><div class="notice">评估结果是候选风险，不等于动态攻击成功。建议先运行内置正反案例，了解检测范围与误报边界。</div>`);
  if (projects.some(project => project.project_status === 'running')) pollTimer = setTimeout(render, 3000);
}

async function newProjectPage() {
  importFiles = [];
  importMode = 'upload';
  shell(`<div class="topline"><div><div class="eyebrow">SOURCE / IMPORT</div><h1>上传源码评估</h1><div class="muted">导入代码，自动保存、分析并生成报告。</div></div><a href="#projects">返回项目列表</a></div><form id="import-form" class="source-import"><nav class="import-modes" aria-label="源码导入方式"><button type="button" data-action="import-mode" data-mode="upload" aria-pressed="true">上传文件 / ZIP</button><button type="button" data-action="import-mode" data-mode="paste" aria-pressed="false">粘贴代码</button></nav><section id="import-upload"><div id="source-dropzone" class="source-dropzone"><div class="import-file-icon" aria-hidden="true">↑</div><h2>拖入源码文件或 ZIP 压缩包</h2><p class="muted">支持多个 .py 文件，也可以直接选择项目文件夹。</p><div class="actions"><button type="button" class="primary" data-action="pick-files">选择源码文件</button><button type="button" data-action="pick-folder">选择文件夹</button></div><input type="file" id="source-files" accept=".py,.zip" multiple hidden><input type="file" id="source-folder" webkitdirectory multiple hidden><small>最多 200 个 Python 文件 · 单文件 1 MiB · 上传合计 20 MiB</small></div><div id="import-file-list" class="import-file-list" aria-live="polite"></div></section><section id="import-paste" hidden><label>文件名<input name="filename" value="submitted.py" maxlength="180" autocomplete="off"></label><label>Python 源码<textarea name="code" rows="16" maxlength="1048576" spellcheck="false" placeholder="在此粘贴需要评估的 Python 代码"></textarea></label></section><details class="import-options"><summary>项目名称与评估说明 <span class="muted">可选</span></summary><div class="form-grid"><label>项目名称<input name="project_name" maxlength="160" placeholder="自动使用文件或压缩包名称"></label><label>评估说明<input name="task_content" maxlength="10000" placeholder="例如：重点检查 SQL 与命令注入"></label></div></details><div class="import-footer"><div><p>仅分析源码，不执行上传的程序。</p><small class="muted">无需设置目录或修改配置；已启用的模型会自动参与复核。</small></div><button class="primary" id="import-start" type="submit">上传并开始评估 →</button></div><div id="import-progress" class="import-progress" role="status" hidden><progress max="100" value="0"></progress><p></p></div><p id="import-error" class="import-error" role="alert" hidden></p></form><details class="advanced-import"><summary>高级接入：服务端目录 / Git 仓库</summary><form id="project-form"><div class="form-grid"><label>项目名称<input name="project_name" required maxlength="160"></label><label>源码类型<select name="source_type"><option value="local">服务端源码目录</option><option value="git">公网 HTTPS Git 仓库</option></select></label><label class="span2">目录或仓库地址<input name="source_path" required maxlength="2048" placeholder="服务端允许的目录，或 HTTPS Git 仓库地址"></label><label>环境类型<select name="environment_type"><option value="static">静态分析（不执行代码）</option><option value="docker">Docker 隔离环境</option></select></label><label>评估说明<input name="task_content" maxlength="10000"></label></div><p class="help">仅高级接入需要服务端目录授权或可用的 Docker 环境。</p><button class="primary">创建项目</button></form></details>`);
}

function formatBytes(bytes) {
  return bytes >= 1048576 ? `${(bytes / 1048576).toFixed(1)} MiB` : `${Math.max(1,Math.ceil(bytes / 1024))} KiB`;
}

function renderImportFiles() {
  const target = document.querySelector('#import-file-list');
  if (!target) return;
  target.innerHTML = importFiles.length ? `<div class="panel-head"><strong>已选 ${importFiles.length} 项 · ${formatBytes(importFiles.reduce((sum,item) => sum + item.file.size,0))}</strong><button type="button" data-action="clear-import" class="quiet-button">清空</button></div><ul>${importFiles.map((item,index) => `<li><span title="${escapeHTML(item.path)}">${escapeHTML(item.path)}</span><small>${formatBytes(item.file.size)}</small><button type="button" data-action="remove-import" data-index="${index}" aria-label="移除 ${escapeHTML(item.path)}" title="移除文件">×</button></li>`).join('')}</ul>` : '';
}

function addImportFiles(items) {
  const allowed = items.filter(item => /\.(py|zip)$/i.test(item.path) && !item.path.split('/').some(part => ['.git','.venv','venv','node_modules','__pycache__','.idea','.agents','.codex','.aws','data','__MACOSX','dist','build'].includes(part) || part.startsWith('.')));
  const merged = new Map(importFiles.map(item => [item.path.toLowerCase(),item]));
  for (const item of allowed) merged.set(item.path.toLowerCase(),item);
  const next = [...merged.values()];
  if (next.length > 200 || next.reduce((sum,item) => sum + item.file.size,0) > 20 * 1048576) return toast('一次最多选择 200 项，文件合计不能超过 20 MiB',true);
  if (next.some(item => /\.py$/i.test(item.path) && item.file.size > 1048576)) return toast('单个 Python 文件不能超过 1 MiB',true);
  importFiles = next;
  renderImportFiles();
  if (!allowed.length) toast('没有找到 Python 源码，请选择 .py 文件或 ZIP 源码包',true);
}

async function droppedFiles(transfer) {
  const entries = [...transfer.items].map(item => item.webkitGetAsEntry?.()).filter(Boolean);
  if (!entries.length) return [...transfer.files].map(file => ({file,path:file.name}));
  const collected = [];
  let visited = 0;
  async function walk(entry, prefix = '') {
    if (++visited > 10000) throw new Error('文件夹条目过多，请选择较小的源码目录或 ZIP 包');
    if (entry.name.startsWith('.') || ['node_modules','venv','__pycache__','data','dist','build'].includes(entry.name)) return;
    const path = prefix + entry.name;
    if (entry.isFile) {
      if (!/\.(py|zip)$/i.test(path)) return;
      const file = await new Promise((resolve,reject) => entry.file(resolve,reject));
      collected.push({file,path});
      if (collected.length > 200) throw new Error('一次最多导入 200 个源码文件');
    } else if (entry.isDirectory) {
      const reader = entry.createReader();
      while (true) {
        const children = await new Promise((resolve,reject) => reader.readEntries(resolve,reject));
        if (!children.length) break;
        for (const child of children) await walk(child,path + '/');
      }
    }
  }
  for (const entry of entries) await walk(entry);
  return collected;
}

async function startImport(form) {
  if (importBusy) return;
  const data = new FormData();
  data.append('project_name',form.elements.project_name.value);
  data.append('task_content',form.elements.task_content.value);
  if (importMode === 'paste') {
    if (!form.elements.code.value.trim()) throw new Error('请先粘贴需要评估的代码');
    data.append('filename',form.elements.filename.value || 'submitted.py');
    data.append('code',form.elements.code.value);
  } else {
    if (!importFiles.length) throw new Error('请先选择源码文件、文件夹或 ZIP 压缩包');
    for (const item of importFiles) data.append('files',item.file,item.path);
  }
  const progress = form.querySelector('#import-progress');
  const errorBox = form.querySelector('#import-error');
  const start = form.querySelector('#import-start');
  errorBox.hidden = true;
  progress.hidden = false;
  progress.querySelector('progress').value = 0;
  progress.querySelector('p').textContent = '正在上传源码…';
  importBusy = true;
  form.setAttribute('aria-busy','true');
  for (const control of form.querySelectorAll('button,input,textarea')) control.disabled = true;
  start.textContent = '正在导入…';
  try {
    const result = await new Promise((resolve,reject) => {
      const request = new XMLHttpRequest();
      request.open('POST','/api/projects/import');
      request.timeout = 120000;
      request.upload.onprogress = event => {
        if (event.lengthComputable) {
          const percent = Math.round(event.loaded / event.total * 100);
          progress.querySelector('progress').value = percent;
          progress.querySelector('p').textContent = percent === 100 ? '上传完成，正在校验并保存源码…' : `正在上传源码 ${percent}%`;
        }
      };
      request.onload = () => {
        let result;
        try { result = JSON.parse(request.responseText); } catch { return reject(new Error('服务器返回异常，请重试')); }
        if (request.status >= 200 && request.status < 300) resolve(result);
        else reject(new Error(typeof result.detail === 'string' ? result.detail : '导入失败，请检查文件后重试'));
      };
      request.onerror = () => reject(new Error('上传中断，请检查网络后重试'));
      request.ontimeout = () => reject(new Error('上传超时，请在项目列表检查是否已创建评估'));
      request.send(data);
    });
    toast(`${result.message}，导入 ${result.file_count} 个文件${result.skipped_count ? `，忽略 ${result.skipped_count} 个非源码或依赖文件` : ''}`);
    location.hash = `#project/${result.project_id}/${result.started ? 'monitor' : 'overview'}`;
  } catch (error) {
    errorBox.textContent = error.message;
    errorBox.hidden = false;
    throw error;
  } finally {
    importBusy = false;
    form.removeAttribute('aria-busy');
    for (const control of form.querySelectorAll('button,input,textarea')) control.disabled = false;
    start.textContent = importMode === 'paste' ? '开始评估 →' : '上传并开始评估 →';
  }
}

async function examplesPage() {
  const examples = await api('/examples');
  shell(`<div class="eyebrow">SIGNALS / EXAMPLES</div><h1>危险信号 · 正反案例</h1><p class="muted">两组对照：SQL 注入与 Shell 注入。每组包含触发与不触发的实现。</p><div class="grid2">${examples.map((example,index) => `<div class="panel"><div class="panel-head"><h2>${escapeHTML(example.name)}</h2>${badge(index ? 'success' : 'high')}</div><p>预期危险信号：<strong>${example.expected_findings}</strong> 个</p><p class="help">${index ? 'SQL 使用参数占位符；命令使用参数列表、shell=False 并校验 IP 地址。本规则不报这两类注入。' : '函数输入拼接 SQL 查询；函数输入拼接字符串并开启 shell=True。两条输入到危险调用的数据流将触发告警。'}</p><pre>${escapeHTML(index ? 'connection.execute("SELECT ... WHERE username = ?", (username,))\nsubprocess.run(["ping", address], shell=False, timeout=5)' : 'query = "SELECT ... WHERE username = \'" + username + "\'"\nconnection.execute(query)\nsubprocess.run("ping " + hostname, shell=True, timeout=5)')}</pre><p class="help">${escapeHTML(example.path)}</p><button class="${index ? '' : 'primary'}" data-action="example" data-index="${index}">创建并启动${index ? '安全' : '危险'}案例 →</button></div>`).join('')}</div><div class="notice">“不触发”仅表示当前静态规则未命中，不保证系统绝对安全。示例源码仅供分析；评估器不会调用其中的 SQL 或系统命令。</div>`, 'examples');
}

function tabs(projectId, active) {
  return `<nav class="tabs">${[['overview','项目概览'],['submit','提交代码'],['monitor','实时监控'],['vulnerabilities','漏洞与证据'],['paths','攻击路径'],['report','评估报告']].map(([key,title]) => `<a href="#project/${projectId}/${key}" class="${key === active ? 'active' : ''}">${title}</a>`).join('')}</nav>`;
}

function stageSteps(records) {
  return `<div class="steps">${Object.entries(stages).map(([name,title],index) => {const stage = records.find(record => record.stage_name === name);return `<div class="step ${stage?.stage_status || ''}"><b>0${index + 1} &nbsp; ${title}</b>${badge(stage?.stage_status || 'idle')}</div>`;}).join('')}</div>`;
}

async function projectPage(projectId, tab = 'overview', renderGeneration) {
  const [project, stageRecords] = await Promise.all([api(`/projects/${projectId}`), api(`/projects/${projectId}/stages`)]);
  let content = '';
  if (tab === 'overview') {
    content = `<div class="stats">${[['危险信号',project.vulnerability_count],['候选攻击路径',project.attack_path_count],['已完成阶段',stageRecords.filter(stage => stage.stage_status === 'success').length],['评估报告',project.report_count]].map(([title,number]) => `<div class="stat"><small>${title}</small><strong>${number}</strong></div>`).join('')}</div><div class="panel"><h2>执行阶段</h2>${stageSteps(stageRecords)}</div><div class="grid2"><div class="panel"><h2>项目基本信息</h2><dl class="kv"><dt>源码位置</dt><dd>${escapeHTML(project.source_path)}</dd><dt>任务说明</dt><dd>${escapeHTML(project.task_content || '默认安全评估')}</dd><dt>隔离环境</dt><dd>${escapeHTML(project.environment_type)} / ${escapeHTML(project.environment_id)}</dd><dt>创建时间</dt><dd>${date(project.created_at)}</dd><dt>启动时间</dt><dd>${date(project.started_at)}</dd><dt>完成时间</dt><dd>${date(project.finished_at)}</dd></dl></div><div class="panel"><h2>评估范围与状态</h2><p>当前状态：${badge(project.project_status)}</p><p class="muted">Python 源码 AST 数据流规则：SQL 注入、Shell 命令注入、动态代码注入。六类工作角色独立记录执行过程。</p><div class="notice warning">静态复核 ≠ 动态利用成功；候选攻击路径不代表已验证的攻击链。</div>${project.error_message ? `<pre>${escapeHTML(project.error_message)}</pre>` : ''}</div></div>`;
   } else if (tab === 'submit') {
    const [submissions, analyses] = await Promise.all([api(`/projects/${projectId}/submissions`),api(`/projects/${projectId}/submission-analyses`)]);
    content = `<div class="panel"><div class="panel-head"><h2>提交代码并立即分析</h2><span class="muted">确定性规则 + 可选大语言模型</span></div><p class="help">提交代码会保存至 MySQL，规则结果、模型结果和分析状态都会持久化。系统不会执行提交的代码。</p><form id="submission-form"><div class="form-grid"><label>文件名<input name="filename" value="submitted.py" required pattern="[A-Za-z0-9_.-]+"></label><label>语言<select name="language"><option value="python">Python</option></select></label><label class="span2">源码<textarea name="code" required maxlength="1048576" rows="18" placeholder="在此粘贴要评估的 Python 代码"></textarea></label></div><div class="form-actions"><button class="primary">提交并分析 →</button></div></form></div><div class="panel"><h2>已入库的代码与分析记录</h2>${submissions.map(saved => {const analysis = analyses.find(item => item.submission_id === saved.id);return `<details><summary><strong>#${saved.id} ${escapeHTML(saved.filename)}</strong><small>${date(saved.created_at)}</small>${badge(analysis?.llm_status || 'pending')}</summary><p>${escapeHTML(analysis?.llm_summary || '等待分析')}</p><button type="button" data-action="load-submission" data-id="${saved.id}">从数据库读取源码</button></details>`;}).join('') || empty('暂无提交记录')}</div>`;
   } else if (tab === 'monitor') {
    const [workers,logs,messages,resources] = await Promise.all(['workers','logs','messages','resources'].map(name => api(`/projects/${projectId}/${name}?limit=2000`)));
    const usage = resources.at(-1);
    content = `${stageSteps(stageRecords)}<div class="stats"><div class="stat"><small>后端进程 CPU（多核累计）</small><strong>${usage?.cpu_usage ?? 0}<small>%</small></strong></div><div class="stat"><small>后端进程 RSS</small><strong>${usage?.memory_usage ?? 0}<small> MiB</small></strong></div><div class="stat"><small>Token（暂未统计）</small><strong>0</strong></div><div class="stat"><small>已保存日志</small><strong>${logs.length}</strong></div></div><div class="grid2"><div class="panel"><h2>角色执行状态</h2>${Object.entries(roles).map(([role,title]) => {const worker = workers.filter(item => item.worker_role === role).at(-1);return `<div class="worker"><div>${title}<small>${escapeHTML(worker?.error_message || worker?.result_summary || worker?.task_content || '等待任务分发')}</small></div>${badge(worker?.task_status || 'idle')}</div>`;}).join('')}</div><div class="panel"><div class="panel-head"><h2>运行日志</h2><span id="stream-status" class="muted">连接实时通道…</span></div><div class="terminal" id="logs">${logs.map(log => `<div class="${escapeHTML(log.log_level)}">[${date(log.created_at)}] ${escapeHTML(log.log_level.toUpperCase())} ${escapeHTML(log.log_content)}</div>`).join('') || '等待运行日志…'}</div></div></div><div class="panel"><h2>角色消息</h2><div class="messages">${messages.map(message => `<div class="message"><b>${escapeHTML(roles[message.worker_role])}</b> <small>${date(message.created_at)}</small><br>${escapeHTML(message.message_text)}</div>`).join('') || empty('暂无消息')}</div></div><p class="help">资源为后端进程统计，非容器独占值。实时通道断线时，页面每 3 秒轮询恢复状态；最多显示前 2000 条，完整日志保存在项目数据目录。</p>`;
  } else if (tab === 'vulnerabilities') {
    const findings = await api(`/projects/${projectId}/vulnerabilities${selectedRisk ? '?risk_level=' + selectedRisk : ''}`);
    content = `<div class="panel"><div class="panel-head"><h2>危险信号与可回溯证据 · ${findings.length}</h2><select id="risk-filter" class="filter"><option value="">所有风险等级</option>${['critical','high','medium','low','info'].map(value => `<option value="${value}" ${selectedRisk === value ? 'selected' : ''}>${labels[value]}</option>`).join('')}</select></div>${findings.map(finding => `<details><summary>${badge(finding.risk_level)}<strong>${escapeHTML(finding.vuln_title)}</strong><small>${escapeHTML(finding.vuln_code)} · ${escapeHTML(finding.file_path)}:${finding.line_number}</small>${badge(finding.verify_status)}</summary><h3>影响说明</h3><p>${escapeHTML(finding.impact_text)}</p><h3>触发条件</h3><p>${escapeHTML(finding.condition_text)}</p><h3>源码证据</h3><pre>${escapeHTML(finding.evidence_text)}</pre><h3>复现步骤（授权环境人工执行）</h3><pre>${escapeHTML(finding.reproduce_steps_text)}</pre><h3>验证方式</h3><pre>${escapeHTML(finding.verify_code_text)}</pre><h3>修复建议</h3><p>${escapeHTML(finding.remediation_text)}</p></details>`).join('') || empty('当前没有符合条件的危险信号。未命中不等于不存在安全风险。')}</div>`;
  } else if (tab === 'paths') {
    const paths = await api(`/projects/${projectId}/attack-paths`);
    content = `<div class="notice warning">以下是单漏洞候选路径，依据静态数据流整理。入口可控性、利用前提和最终影响需要人工复核；没有虚构跨漏洞串联。</div>${paths.map(path => `<div class="panel"><div class="panel-head"><h2>${escapeHTML(path.path_title)}</h2><small>${escapeHTML(path.path_code)}</small></div><p class="muted">${escapeHTML(path.path_summary)}</p><div class="path-flow"><div class="path-node">潜在外部输入</div><span class="path-arrow">→</span>${path.items.map(item => `<div class="path-node">${item.step_order}. ${escapeHTML(item.vuln_code)}<br>${escapeHTML(item.vuln_title)}</div><span class="path-arrow">→</span>`).join('')}<div class="path-node">危险调用 · 待人工确认</div></div>${path.items.map(item => `<p class="help">${escapeHTML(item.step_text)}</p>`).join('')}<p>最终潜在影响：${escapeHTML(path.final_impact_text)}</p></div>`).join('') || empty('暂无候选攻击路径')}`;
  } else if (tab === 'report') {
    if (project.report_count) {
      const report = await api(`/projects/${projectId}/report`);
      content = `<div class="panel"><div class="panel-head"><h2>安全评估报告</h2><div class="actions"><a href="/api/projects/${projectId}/report/download?format=md">下载 Markdown ↓</a><a href="/api/projects/${projectId}/report/download?format=html">下载 HTML ↓</a></div></div><pre class="report">${escapeHTML(report.report_markdown)}</pre></div>`;
    } else content = `<div class="panel">${empty('报告尚未生成。启动评估并等待报告整理阶段完成。')}</div>`;
  }
  if (renderGeneration !== generation) return;
  shell(`<div class="topline"><div><div class="eyebrow">PROJECT / #${projectId}</div><h1>${escapeHTML(project.project_name)}</h1><div class="actions">${badge(project.project_status)}<small>${escapeHTML(project.source_type)} · ${escapeHTML(project.environment_type)}</small></div></div><div class="actions">${project.project_status === 'created' ? `<button class="primary" data-action="start" data-id="${projectId}">▶ 启动评估</button>` : ''}${project.project_status === 'running' ? `<button data-action="stop" data-id="${projectId}">■ 停止任务</button>` : `<button class="danger" data-action="delete" data-id="${projectId}">删除项目</button>`}<a href="#projects">返回列表</a></div></div>${tabs(projectId,tab)}${content}`);
  const logBox = document.querySelector('#logs');
  if (logBox) logBox.scrollTop = logBox.scrollHeight;
  if (project.project_status === 'running' || tab === 'monitor') connectStream(projectId, project.project_status);
  if (project.project_status === 'running') pollTimer = setTimeout(render, 3000);
}

function connectStream(projectId, currentStatus) {
  socket = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/api/projects/${projectId}/stream`);
  socket.onopen = () => {const status = document.querySelector('#stream-status'); if (status) status.textContent = '● 实时连接';};
  socket.onmessage = event => {
    const message = JSON.parse(event.data);
    if (message.type === 'heartbeat' || (message.type === 'project_status' && message.data.project_status === currentStatus)) return;
    if (!refreshTimer) refreshTimer = setTimeout(() => {refreshTimer = null; render();}, 650);
  };
  socket.onclose = () => {const status = document.querySelector('#stream-status'); if (status) status.textContent = '通道断开 · 轮询恢复';};
}

async function configPage() {
  if (user.role !== 'admin') throw new Error('需要管理员权限');
  const [config,logs,llm] = await Promise.all([api('/system/config'),api('/system/logs'),api('/system/llm/config')]);
  const names = {default_timeout:'任务总超时（秒）',max_concurrency:'最大并发任务数',retention_days:'保留天数策略',docker_image:'Docker 镜像',max_files:'最大 Python 文件数',max_file_bytes:'单文件大小上限（字节）'};
  shell(`<div class="eyebrow">ADMIN / CONFIGURATION</div><h1>系统运行配置</h1><p class="muted">配置变更仅对新任务生效。修改环境范围请使用服务端环境变量。</p><form id="config-form" class="panel"><div class="form-grid">${Object.entries(names).map(([key,title]) => `<label>${title}<input name="${key}" value="${escapeHTML(config[key])}" type="${key === 'docker_image' ? 'text' : 'number'}" required></label>`).join('')}<label>公网 Git 接入<select name="allow_git"><option value="true" ${config.allow_git ? 'selected' : ''}>允许</option><option value="false" ${!config.allow_git ? 'selected' : ''}>禁止</option></select></label></div><div class="notice warning">保留天数仅作为策略配置，当前不会自动删除评估数据；需在项目页手动删除。Docker 镜像须预先由管理员拉取。</div><div class="form-actions"><button class="primary">保存运行配置</button></div></form><form id="llm-form" class="panel"><div class="panel-head"><h2>大语言模型配置</h2><span class="status-line"><span class="dot"></span>${llm.api_key_configured ? 'API Key 已配置' : 'API Key 未配置'}</span></div><div class="form-grid"><label>启用<select name="enabled"><option value="false" ${!llm.enabled ? 'selected' : ''}>关闭（默认）</option><option value="true" ${llm.enabled ? 'selected' : ''}>启用</option></select></label><label>模型名称<input name="model" value="${escapeHTML(llm.model)}" required></label><label class="span2">OpenAI 兼容 Base URL<input name="base_url" value="${escapeHTML(llm.base_url)}" required></label><label>API Key<input name="api_key" type="password" autocomplete="new-password" placeholder="留空保持原 Key"></label><label>调用超时（秒）<input name="timeout_seconds" type="number" min="5" max="300" value="${llm.timeout_seconds}" required></label><label>最大送审字符数<input name="max_code_chars" type="number" min="1000" max="50000" value="${llm.max_code_chars}" required></label><label class="span2">系统提示词<textarea name="system_prompt" rows="4" required>${escapeHTML(llm.system_prompt)}</textarea></label></div><div class="notice">配置位置：本页「系统配置 → 大语言模型配置」。可在 .env 中设置 SAFETY_LLM_API_KEY、SAFETY_LLM_BASE_URL、SAFETY_LLM_MODEL 和 SAFETY_LLM_ENABLED；非空环境配置优先，修改后需重启。密钥不回显，模型仅接收送审代码。${llm.environment_overrides.length ? '<br>环境配置优先的字段：' + escapeHTML(llm.environment_overrides.join('、')) : ''}</div><div class="form-actions"><button type="submit" class="primary">保存 LLM 配置</button><button type="button" data-action="test-llm">测试已保存的连接</button><span id="llm-test-result" role="status"></span></div></form><div class="grid2"><form id="user-form" class="panel"><h2>创建使用者账户</h2><label>用户名<input name="username" required minlength="3" maxlength="80"></label><label>初始密码<input name="password" type="password" required minlength="8" autocomplete="new-password"></label><label>角色<select name="role"><option value="user">普通使用者</option><option value="admin">管理员</option></select></label><button>创建账户</button></form><div class="panel"><h2>系统操作审计 · 最近 200 条</h2><div class="terminal">${logs.map(log => `<div>[${date(log.created_at)}] ${escapeHTML(log.action)} · ${escapeHTML(log.detail)}</div>`).join('')}</div></div></div>`, 'config');
}

async function render() {
  generation += 1;
  const renderGeneration = generation;
  clearTimeout(pollTimer);
  clearTimeout(refreshTimer);
  refreshTimer = null;
  if (socket) {socket.onclose = null; socket.close(); socket = null;}
  try {
    if (!user) {try {user = await api('/system/me');} catch {return await authPage();}}
    const [page,id,tab] = location.hash.slice(1).split('/');
    if (page === 'new') await newProjectPage();
    else if (page === 'examples') await examplesPage();
    else if (page === 'config') await configPage();
    else if (page === 'project' && /^\d+$/.test(id)) await projectPage(Number(id),tab || 'overview',renderGeneration);
    else await projectsPage();
  } catch (error) {toast(error.message,true); if (!user) await authPage();}
}

document.addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.target;
  const body = Object.fromEntries(new FormData(form));
  const button = form.querySelector('button[type="submit"], button:not([type])');
  if (button) button.disabled = true;
  try {
    if (form.id === 'import-form') {
      await startImport(form);
    } else if (form.id === 'auth-form') {
      if (form.dataset.init === 'true') await api('/system/init',{method:'POST',body:JSON.stringify(body)});
      user = await api('/system/login',{method:'POST',body:JSON.stringify(body)});
      location.hash = '#projects';
      await render();
    } else if (form.id === 'project-form') {
      const project = await api('/projects',{method:'POST',body:JSON.stringify(body)});
      location.hash = `#project/${project.id}`;
     } else if (form.id === 'submission-form') {
       const projectId = location.hash.split('/')[1];
       const result = await api(`/projects/${projectId}/submissions`,{method:'POST',body:JSON.stringify(body)});
       toast(`提交 #${result.id} 完成：规则命中 ${result.analysis.static.length} 条；LLM 状态 ${result.analysis.llm_status}`);
       location.hash = `#project/${projectId}/vulnerabilities`;
     } else if (form.id === 'llm-form') {
       body.enabled = body.enabled === 'true';
       body.timeout_seconds = Number(body.timeout_seconds); body.max_code_chars = Number(body.max_code_chars);
       await api('/system/llm/config',{method:'PUT',body:JSON.stringify(body)});
       toast('大语言模型配置已保存');
       await render();
     } else if (form.id === 'config-form') {
      for (const key of Object.keys(body)) if (key !== 'docker_image') body[key] = key === 'allow_git' ? body[key] === 'true' : Number(body[key]);
      await api('/system/config',{method:'PUT',body:JSON.stringify(body)});
      toast('运行配置已保存');
    } else if (form.id === 'user-form') {
      await api('/system/users',{method:'POST',body:JSON.stringify(body)});
      form.reset(); toast('用户已创建');
    }
  } catch (error) {toast(error.message,true);} finally {if (button) button.disabled = false;}
});

document.addEventListener('click', async event => {
  const button = event.target.closest('[data-action]');
  if (!button) return;
  const action = button.dataset.action;
  button.disabled = true;
  try {
    if (action === 'pick-files') document.querySelector('#source-files').click();
    else if (action === 'pick-folder') document.querySelector('#source-folder').click();
    else if (action === 'import-mode') {
      importMode = button.dataset.mode;
      document.querySelector('#import-upload').hidden = importMode !== 'upload';
      document.querySelector('#import-paste').hidden = importMode !== 'paste';
      for (const choice of document.querySelectorAll('[data-action=import-mode]')) choice.setAttribute('aria-pressed',String(choice.dataset.mode === importMode));
      document.querySelector('#import-start').textContent = importMode === 'paste' ? '开始评估 →' : '上传并开始评估 →';
    } else if (action === 'remove-import') {importFiles.splice(Number(button.dataset.index),1);renderImportFiles();}
    else if (action === 'clear-import') {importFiles = [];renderImportFiles();}
    else if (action === 'logout') {await api('/system/logout',{method:'POST'});user = null;await render();}
    else if (action === 'test-llm') {
      const target = document.querySelector('#llm-test-result');
      target.textContent = '正在请求模型，请稍候…';
      const result = await api('/system/llm/test',{method:'POST'});
      target.textContent = result.message;
      toast(result.message,!result.reachable);
    } else if (action === 'load-submission') {
      const projectId = location.hash.split('/')[1];
      const saved = await api(`/projects/${projectId}/submissions/${button.dataset.id}`);
      const form = document.querySelector('#submission-form');
      form.elements.filename.value = saved.filename;
      form.elements.code.value = saved.code_text;
      toast('已从数据库读取保存的源码');
    } else if (action === 'example') {
      const examples = await api('/examples');
      const example = examples[Number(button.dataset.index)];
      const project = await api('/projects',{method:'POST',body:JSON.stringify({project_name:example.name,source_type:'local',source_path:example.path,task_content:`正反案例演示：预期 ${example.expected_findings} 条信号。`,environment_type:'static'})});
      await api(`/projects/${project.id}/start`,{method:'POST'});
      location.hash = `#project/${project.id}/monitor`;
    } else if (action === 'delete') {
      if (!confirm('确认删除该项目及全部漏洞、路径、报告、日志与临时文件？操作审计仍会保留。')) return;
      await api(`/projects/${button.dataset.id}`,{method:'DELETE'});
      location.hash = '#projects';toast('项目及关联数据已删除');
    } else if (action === 'start' || action === 'stop') {
      await api(`/projects/${button.dataset.id}/${action}`,{method:'POST'});
      if (action === 'start') location.hash = `#project/${button.dataset.id}/monitor`;
      await render();
    }
  } catch (error) {toast(error.message,true);} finally {button.disabled = false;}
});
document.addEventListener('change', event => {
  if (['source-files','source-folder'].includes(event.target.id)) {
    addImportFiles([...event.target.files].map(file => ({file,path:file.webkitRelativePath || file.name})));
    event.target.value = '';
  } else if (event.target.id === 'risk-filter') {selectedRisk = event.target.value;render();}
});
document.addEventListener('dragover', event => {
  const target = event.target.closest('#source-dropzone');
  if (target) {event.preventDefault();if (!importBusy) target.classList.add('drag-active');}
});
document.addEventListener('dragleave', event => {
  const target = event.target.closest('#source-dropzone');
  if (target && !target.contains(event.relatedTarget)) target.classList.remove('drag-active');
});
document.addEventListener('drop', async event => {
  const target = event.target.closest('#source-dropzone');
  if (!target) return;
  event.preventDefault();
  target.classList.remove('drag-active');
  if (importBusy) return;
  try { addImportFiles(await droppedFiles(event.dataTransfer)); } catch (error) {toast(error.message,true);}
});
window.addEventListener('hashchange',render);
render();
