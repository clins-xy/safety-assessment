PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin','user')), status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT, project_name TEXT NOT NULL, source_type TEXT NOT NULL,
    source_path TEXT NOT NULL, task_content TEXT NOT NULL DEFAULT '', environment_type TEXT NOT NULL DEFAULT 'static',
    environment_id TEXT NOT NULL UNIQUE, project_status TEXT NOT NULL DEFAULT 'created',
    created_by INTEGER NOT NULL REFERENCES users(id), created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    started_at TEXT, finished_at TEXT, error_message TEXT
);
CREATE TABLE IF NOT EXISTS runtime_stages (
    id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    stage_name TEXT NOT NULL, stage_status TEXT NOT NULL, started_at TEXT, finished_at TEXT, error_message TEXT
);
CREATE TABLE IF NOT EXISTS worker_tasks (
    id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    stage_id INTEGER REFERENCES runtime_stages(id) ON DELETE CASCADE, worker_role TEXT NOT NULL,
    task_content TEXT NOT NULL, task_status TEXT NOT NULL, result_summary TEXT, started_at TEXT, finished_at TEXT, error_message TEXT
);
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    vuln_code TEXT NOT NULL, vuln_title TEXT NOT NULL, risk_level TEXT NOT NULL, file_path TEXT NOT NULL,
    line_number INTEGER NOT NULL, rule_id TEXT NOT NULL, impact_text TEXT NOT NULL, condition_text TEXT NOT NULL,
    evidence_text TEXT NOT NULL, verify_status TEXT NOT NULL DEFAULT 'pending', reproduce_steps_text TEXT NOT NULL,
    verify_code_text TEXT NOT NULL DEFAULT '', remediation_text TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS attack_paths (
    id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    path_code TEXT NOT NULL, path_title TEXT NOT NULL, path_summary TEXT NOT NULL, final_impact_text TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS attack_path_items (
    id INTEGER PRIMARY KEY, path_id INTEGER NOT NULL REFERENCES attack_paths(id) ON DELETE CASCADE,
    vuln_id INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE, step_order INTEGER NOT NULL, step_text TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS chat_messages (
    id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    worker_role TEXT NOT NULL, message_type TEXT NOT NULL, message_text TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runtime_logs (
    id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    stage_id INTEGER REFERENCES runtime_stages(id) ON DELETE SET NULL,
    worker_task_id INTEGER REFERENCES worker_tasks(id) ON DELETE SET NULL,
    log_level TEXT NOT NULL, log_content TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS resource_usages (
    id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    cpu_usage REAL NOT NULL, memory_usage REAL NOT NULL, token_count INTEGER NOT NULL DEFAULT 0, recorded_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    report_markdown TEXT NOT NULL, report_html TEXT NOT NULL, report_file_path TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS code_submissions (
    id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    filename TEXT NOT NULL, language TEXT NOT NULL, code_text TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS llm_analyses (
    id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    submission_id INTEGER REFERENCES code_submissions(id) ON DELETE CASCADE,
    filename TEXT NOT NULL, provider TEXT NOT NULL, model TEXT NOT NULL, status TEXT NOT NULL,
    summary TEXT NOT NULL, result_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS submission_analyses (
    id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    submission_id INTEGER NOT NULL REFERENCES code_submissions(id) ON DELETE CASCADE,
    static_result_json TEXT NOT NULL, llm_analysis_id INTEGER REFERENCES llm_analyses(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS system_config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_projects_owner ON projects(created_by);
CREATE INDEX IF NOT EXISTS idx_logs_project ON runtime_logs(project_id, id);
CREATE INDEX IF NOT EXISTS idx_vulns_project ON vulnerabilities(project_id);
