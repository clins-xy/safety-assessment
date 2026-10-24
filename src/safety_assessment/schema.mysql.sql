CREATE TABLE IF NOT EXISTS users (
    id BIGINT PRIMARY KEY AUTO_INCREMENT, username VARCHAR(80) NOT NULL UNIQUE, password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(16) NOT NULL, status VARCHAR(16) NOT NULL DEFAULT 'active', created_at VARCHAR(40) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS sessions (
    token_hash VARCHAR(64) PRIMARY KEY, user_id BIGINT NOT NULL, expires_at DOUBLE NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS projects (
    id BIGINT PRIMARY KEY AUTO_INCREMENT, project_name VARCHAR(160) NOT NULL, source_type VARCHAR(16) NOT NULL,
    source_path TEXT NOT NULL, task_content TEXT NOT NULL, environment_type VARCHAR(16) NOT NULL DEFAULT 'static',
    environment_id VARCHAR(80) NOT NULL UNIQUE, project_status VARCHAR(16) NOT NULL DEFAULT 'created',
    created_by BIGINT NOT NULL, created_at VARCHAR(40) NOT NULL, updated_at VARCHAR(40) NOT NULL,
    started_at VARCHAR(40), finished_at VARCHAR(40), error_message TEXT,
    FOREIGN KEY (created_by) REFERENCES users(id), INDEX idx_projects_owner(created_by)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS runtime_stages (
    id BIGINT PRIMARY KEY AUTO_INCREMENT, project_id BIGINT NOT NULL, stage_name VARCHAR(40) NOT NULL,
    stage_status VARCHAR(16) NOT NULL, started_at VARCHAR(40), finished_at VARCHAR(40), error_message TEXT,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS worker_tasks (
    id BIGINT PRIMARY KEY AUTO_INCREMENT, project_id BIGINT NOT NULL, stage_id BIGINT,
    worker_role VARCHAR(40) NOT NULL, task_content TEXT NOT NULL, task_status VARCHAR(16) NOT NULL,
    result_summary TEXT, started_at VARCHAR(40), finished_at VARCHAR(40), error_message TEXT,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (stage_id) REFERENCES runtime_stages(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id BIGINT PRIMARY KEY AUTO_INCREMENT, project_id BIGINT NOT NULL, vuln_code VARCHAR(80) NOT NULL,
    vuln_title VARCHAR(255) NOT NULL, risk_level VARCHAR(16) NOT NULL, file_path TEXT NOT NULL,
    line_number INT NOT NULL, rule_id VARCHAR(80) NOT NULL, impact_text TEXT NOT NULL, condition_text TEXT NOT NULL,
    evidence_text MEDIUMTEXT NOT NULL, verify_status VARCHAR(32) NOT NULL DEFAULT 'pending',
    reproduce_steps_text TEXT NOT NULL, verify_code_text TEXT NOT NULL, remediation_text TEXT NOT NULL, created_at VARCHAR(40) NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE, INDEX idx_vulns_project(project_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS attack_paths (
    id BIGINT PRIMARY KEY AUTO_INCREMENT, project_id BIGINT NOT NULL, path_code VARCHAR(80) NOT NULL,
    path_title VARCHAR(255) NOT NULL, path_summary TEXT NOT NULL, final_impact_text TEXT NOT NULL, created_at VARCHAR(40) NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS attack_path_items (
    id BIGINT PRIMARY KEY AUTO_INCREMENT, path_id BIGINT NOT NULL, vuln_id BIGINT NOT NULL, step_order INT NOT NULL, step_text TEXT NOT NULL,
    FOREIGN KEY (path_id) REFERENCES attack_paths(id) ON DELETE CASCADE,
    FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS chat_messages (
    id BIGINT PRIMARY KEY AUTO_INCREMENT, project_id BIGINT NOT NULL, worker_role VARCHAR(40) NOT NULL,
    message_type VARCHAR(32) NOT NULL, message_text TEXT NOT NULL, created_at VARCHAR(40) NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS runtime_logs (
    id BIGINT PRIMARY KEY AUTO_INCREMENT, project_id BIGINT NOT NULL, stage_id BIGINT, worker_task_id BIGINT,
    log_level VARCHAR(16) NOT NULL, log_content TEXT NOT NULL, created_at VARCHAR(40) NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (stage_id) REFERENCES runtime_stages(id) ON DELETE SET NULL,
    FOREIGN KEY (worker_task_id) REFERENCES worker_tasks(id) ON DELETE SET NULL, INDEX idx_logs_project(project_id,id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS resource_usages (
    id BIGINT PRIMARY KEY AUTO_INCREMENT, project_id BIGINT NOT NULL, cpu_usage DOUBLE NOT NULL,
    memory_usage DOUBLE NOT NULL, token_count BIGINT NOT NULL DEFAULT 0, recorded_at VARCHAR(40) NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS reports (
    id BIGINT PRIMARY KEY AUTO_INCREMENT, project_id BIGINT NOT NULL, report_markdown MEDIUMTEXT NOT NULL,
    report_html MEDIUMTEXT NOT NULL, report_file_path TEXT NOT NULL, created_at VARCHAR(40) NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS code_submissions (
    id BIGINT PRIMARY KEY AUTO_INCREMENT, project_id BIGINT NOT NULL, filename VARCHAR(180) NOT NULL,
    language VARCHAR(20) NOT NULL, code_text MEDIUMTEXT NOT NULL, created_at VARCHAR(40) NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS llm_analyses (
    id BIGINT PRIMARY KEY AUTO_INCREMENT, project_id BIGINT NOT NULL, submission_id BIGINT,
    filename VARCHAR(180) NOT NULL, provider VARCHAR(80) NOT NULL, model VARCHAR(160) NOT NULL,
    status VARCHAR(32) NOT NULL, summary TEXT NOT NULL, result_json MEDIUMTEXT NOT NULL, created_at VARCHAR(40) NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (submission_id) REFERENCES code_submissions(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS submission_analyses (
    id BIGINT PRIMARY KEY AUTO_INCREMENT, project_id BIGINT NOT NULL, submission_id BIGINT NOT NULL,
    static_result_json MEDIUMTEXT NOT NULL, llm_analysis_id BIGINT, created_at VARCHAR(40) NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (submission_id) REFERENCES code_submissions(id) ON DELETE CASCADE,
    FOREIGN KEY (llm_analysis_id) REFERENCES llm_analyses(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS system_config (`key` VARCHAR(80) PRIMARY KEY, value TEXT NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT PRIMARY KEY AUTO_INCREMENT, user_id BIGINT, action VARCHAR(80) NOT NULL, detail TEXT NOT NULL, created_at VARCHAR(40) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
