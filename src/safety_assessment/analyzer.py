import ast
from dataclasses import asdict, dataclass


RULES = {
    "SQL_INJECTION": ("外部输入拼接 SQL", "high", "可能绕过查询条件、读取或修改数据库记录。", "使用 execute(sql, parameters) 参数绑定，不拼接 SQL。"),
    "COMMAND_INJECTION": ("外部输入进入 Shell 命令", "critical", "可能以服务账户权限执行非预期系统命令。", "使用固定程序和参数列表，禁用 shell=True，校验参数白名单。"),
    "CODE_INJECTION": ("外部输入进入动态代码执行", "critical", "可能执行攻击者控制的 Python 表达式或代码。", "移除 eval/exec；按业务使用 JSON 解析及严格类型校验。"),
}


@dataclass
class Finding:
    rule_id: str
    vuln_title: str
    risk_level: str
    file_path: str
    line_number: int
    impact_text: str
    condition_text: str
    evidence_text: str
    reproduce_steps_text: str
    verify_code_text: str
    remediation_text: str

    def to_dict(self):
        return asdict(self)


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{dotted(node.value)}.{node.attr}"
    return ""


class Analyzer(ast.NodeVisitor):
    def __init__(self, source: str, filename: str):
        self.source = source
        self.filename = filename
        self.lines = source.splitlines()
        self.tainted: set[str] = set()
        self.findings: list[Finding] = []
        self.aliases: dict[str, str] = {}

    def visit_Import(self, node):
        for alias in node.names:
            self.aliases[alias.asname or alias.name] = alias.name

    def visit_ImportFrom(self, node):
        for alias in node.names:
            self.aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    def name(self, node):
        name = dotted(node)
        root, _, suffix = name.partition(".")
        return self.aliases.get(root, root) + (f".{suffix}" if suffix else "")

    def is_tainted(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted
        if isinstance(node, ast.Call):
            name = self.name(node.func)
            if name == "input" or any(part in name for part in (
                "request.args", "request.form", "request.json", "request.get_json", "request.values",
                "request.query_params", "request.GET", "request.POST",
            )):
                return True
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            name = self.name(node.value)
            if name.startswith(("request.", "sys.argv")):
                return True
        return any(self.is_tainted(child) for child in ast.iter_child_nodes(node))

    def visit_FunctionDef(self, node):
        previous = self.tainted.copy()
        self.tainted = {argument.arg for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)}
        for statement in node.body:
            self.visit(statement)
        self.tainted = previous

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node):
        tainted = self.is_tainted(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if tainted:
                    self.tainted.add(target.id)
                else:
                    self.tainted.discard(target.id)
        self.visit(node.value)

    def visit_AnnAssign(self, node):
        if isinstance(node.target, ast.Name):
            if self.is_tainted(node.value):
                self.tainted.add(node.target.id)
            else:
                self.tainted.discard(node.target.id)
        if node.value:
            self.visit(node.value)

    def visit_AugAssign(self, node):
        if isinstance(node.target, ast.Name) and self.is_tainted(node.value):
            self.tainted.add(node.target.id)
        self.visit(node.value)

    def visit_If(self, node):
        self.visit(node.test)
        before = self.tainted.copy()
        for statement in node.body:
            self.visit(statement)
        after_body = self.tainted.copy()
        self.tainted = before
        for statement in node.orelse:
            self.visit(statement)
        self.tainted |= after_body

    def visit_Call(self, node):
        name = self.name(node.func)
        argument = node.args[0] if node.args else next((keyword.value for keyword in node.keywords if keyword.arg in ("args", "command", "sql", "source")), None)
        if self.is_tainted(argument):
            rule = None
            if name.endswith((".execute", ".executemany", ".executescript")):
                rule = "SQL_INJECTION"
            elif name in ("os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"):
                rule = "COMMAND_INJECTION"
            elif name.startswith("subprocess.") and name.rsplit(".", 1)[-1] in ("run", "Popen", "call", "check_call", "check_output"):
                if any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords):
                    rule = "COMMAND_INJECTION"
            elif name in ("eval", "exec", "builtins.eval", "builtins.exec"):
                rule = "CODE_INJECTION"
            if rule:
                self.add(rule, node)
        self.generic_visit(node)

    def add(self, rule: str, node):
        title, risk, impact, remediation = RULES[rule]
        snippet = "\n".join(f"{index + 1}: {self.lines[index]}" for index in range(max(0, node.lineno - 3), min(len(self.lines), node.end_lineno + 1)))
        self.findings.append(Finding(
            rule, title, risk, self.filename, node.lineno, impact,
            "外部输入或函数参数流入危险调用；函数参数是否实际受攻击者控制、认证与部署条件仍需人工确认。",
            snippet,
            f"1. 检查 {self.filename}:{node.lineno} 的入口与权限。\n2. 在授权测试环境使用无副作用标记输入观察数据流。\n3. 对照修复后的参数化/无 Shell 实现验证。不得直接在生产执行。",
            "目标代码不执行。验证器重新解析源码，核对同一规则、文件、行号的数据流命中。",
            remediation,
        ))


def analyze(source: str, filename: str) -> list[dict]:
    analyzer = Analyzer(source, filename)
    analyzer.visit(ast.parse(source, filename=filename))
    return [finding.to_dict() for finding in analyzer.findings]
