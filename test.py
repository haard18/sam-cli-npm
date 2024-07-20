from luaparser import ast, astnodes
import json
import sys

INT_MAX = 2147483647
INT_MIN = -2147483648

vulnerabilities = []

def add_vulnerability(name, description, pattern, severity, line):
    vulnerabilities.append({
        "name": name,
        "description": description,
        "pattern": pattern,
        "severity": severity,
        "line": line
    })

def is_potential_overflow(number):
    return number >= INT_MAX or number <= INT_MIN

def is_potential_underflow(number):
    return number <= INT_MIN or number >= INT_MAX

def get_line_number(node):
    if hasattr(node, 'line') and node.line is not None:
        return node.line
    if hasattr(node, '_parent'):
        return get_line_number(node._parent)
    return None

def analyze_overflow_in_node(node):
    if isinstance(node, (astnodes.AddOp, astnodes.SubOp, astnodes.MultOp)):
        left_operand = node.left
        right_operand = node.right

        if isinstance(left_operand, astnodes.Number) and is_potential_overflow(left_operand.n):
            add_vulnerability(
                "Integer Overflow",
                "Potential integer overflow detected with left operand.",
                "overflow",
                "high",
                get_line_number(left_operand)
            )

        if isinstance(right_operand, astnodes.Number) and is_potential_overflow(right_operand.n):
            add_vulnerability(
                "Integer Overflow",
                "Potential integer overflow detected with right operand.",
                "overflow",
                "high",
                get_line_number(right_operand)
            )

    if isinstance(node, astnodes.LocalAssign):
        for value in node.values:
            if isinstance(value, astnodes.Number) and is_potential_overflow(value.n):
                add_vulnerability(
                    "Integer Overflow",
                    "Potential integer overflow detected with local variable assignment.",
                    "overflow",
                    "high",
                    get_line_number(value)
                )

    if isinstance(node, astnodes.Function):
        for arg in node.args:
            if isinstance(arg, astnodes.Number) and is_potential_overflow(arg.n):
                add_vulnerability(
                    "Integer Overflow",
                    "Potential integer overflow detected with function argument.",
                    "overflow",
                    "high",
                    get_line_number(arg)
                )

def analyze_underflow_in_node(node):
    if isinstance(node, (astnodes.AddOp, astnodes.SubOp, astnodes.MultOp)):
        left_operand = node.left
        right_operand = node.right

        if isinstance(left_operand, astnodes.Number) and is_potential_underflow(left_operand.n):
            add_vulnerability(
                "Integer Underflow",
                "Potential integer underflow detected with left operand.",
                "underflow",
                "high",
                get_line_number(left_operand)
            )

        if isinstance(right_operand, astnodes.Number) and is_potential_underflow(right_operand.n):
            add_vulnerability(
                "Integer Underflow",
                "Potential integer underflow detected with right operand.",
                "underflow",
                "high",
                get_line_number(right_operand)
            )

    if isinstance(node, astnodes.LocalAssign):
        for value in node.values:
            if isinstance(value, astnodes.Number) and is_potential_underflow(value.n):
                add_vulnerability(
                    "Integer Underflow",
                    "Potential integer underflow detected with local variable assignment.",
                    "underflow",
                    "high",
                    get_line_number(value)
                )

    if isinstance(node, astnodes.Function):
        for arg in node.args:
            if isinstance(arg, astnodes.Number) and is_potential_underflow(arg.n):
                add_vulnerability(
                    "Integer Underflow",
                    "Potential integer underflow detected with function argument.",
                    "underflow",
                    "high",
                    get_line_number(arg)
                )

def analyze_overflow_and_return(code):
    tree = ast.parse(code)

    for node in ast.walk(tree):
        analyze_overflow_in_node(node)

        if isinstance(node, astnodes.Function):
            for body_node in ast.walk(node.body):
                analyze_overflow_in_node(body_node)

            if node.name.id == 'another_example':
                for n in node.body.body:
                    if isinstance(n, astnodes.Return):
                        for ret_val in n.values:
                            if isinstance(ret_val, astnodes.Number) and is_potential_overflow(ret_val.n):
                                add_vulnerability(
                                    "Integer Overflow",
                                    f"Potential integer overflow detected in return statement of function '{node.name.id}'.",
                                    "overflow",
                                    "high",
                                    get_line_number(ret_val)
                                )

def analyze_underflow_and_return(code):
    tree = ast.parse(code)

    for node in ast.walk(tree):
        analyze_underflow_in_node(node)

        if isinstance(node, astnodes.Function):
            for body_node in ast.walk(node.body):
                analyze_underflow_in_node(body_node)

            if node.name.id == 'another_example':
                for n in node.body.body:
                    if isinstance(n, astnodes.Return):
                        for ret_val in n.values:
                            if isinstance(ret_val, astnodes.Number) and is_potential_underflow(ret_val.n):
                                add_vulnerability(
                                    "Integer Underflow",
                                    f"Potential integer underflow detected in return statement of function '{node.name.id}'.",
                                    "underflow",
                                    "high",
                                    get_line_number(ret_val)
                                )

def analyze_return(code):
    tree = ast.parse(code)

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Function):
            has_return = any(isinstance(n, astnodes.Return) for n in node.body.body)
            if not has_return:
                add_vulnerability(
                    "Missing Return Statement",
                    "A function is missing a return statement.",
                    "missing_return",
                    "low",
                    get_line_number(node)
                )

def check_private_key_exposure(code):
    tree = ast.parse(code)
    private_key_words = ["privatekey", "private_key", "secretkey", "secret_key", "keypair", "key_pair", "api_key"]

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Assign):
            for target in node.targets:
                if isinstance(target, astnodes.Name) and target.id.lower() in private_key_words:
                    add_vulnerability(
                        "Private Key Exposure",
                        f"Potential exposure of private key in variable '{target.id}'.",
                        "private_key_exposure",
                        "high",
                        get_line_number(node)
                    )

def analyze_reentrancy(code):
    tree = ast.parse(code)

    def is_external_call(node):
        return isinstance(node, astnodes.Call) and isinstance(node.func, astnodes.Name) and node.func.id == "external_call"

    def has_state_change(node):
        return isinstance(node, astnodes.Assign)

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Function):
            body = node.body.body
            for i, n in enumerate(body):
                if is_external_call(n):
                    for subsequent_node in body[i+1:]:
                        if has_state_change(subsequent_node):
                            add_vulnerability(
                                "Reentrancy",
                                "A function calls an external contract before updating its state.",
                                "external_call",
                                "high",
                                get_line_number(node)
                            )

def analyze_floating_pragma(code):
    deprecated_functions = ["setfenv", "getfenv"]
    tree = ast.parse(code)

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Call) and isinstance(node.func, astnodes.Name):
            if node.func.id in deprecated_functions:
                add_vulnerability(
                    "Floating Pragma",
                    f"Floating pragma issue detected with function '{node.func.id}'.",
                    "floating_pragma",
                    "low",
                    get_line_number(node)
                )

def analyze_denial_of_service(code):
    tree = ast.parse(code)

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Call) and isinstance(node.func, astnodes.Name):
            if node.func.id == "perform_expensive_operation":
                add_vulnerability(
                    "Denial of Service",
                    f"Potential Denial of Service vulnerability detected with function '{node.func.id}'.",
                    "denial_of_service",
                    "medium",
                    get_line_number(node)
                )

def analyze_unchecked_external_calls(code):
    tree = ast.parse(code)

    def is_external_call(node):
        return isinstance(node, astnodes.Call) and isinstance(node.func, astnodes.Index) and isinstance(node.func.value, astnodes.Name)

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Function):
            for n in node.body.body:
                if is_external_call(n):
                    add_vulnerability(
                        "Unchecked External Calls",
                        f"Unchecked external call detected in function '{node.name.id}'.",
                        "unchecked_external_call",
                        "medium",
                        get_line_number(n)
                    )

def analyze_greedy_suicidal_functions(code):
    tree = ast.parse(code)

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Function):
            for n in node.body.body:
                if isinstance(n, astnodes.Call) and isinstance(n.func, astnodes.Name) and n.func.id == "transfer_funds":
                    if not any(isinstance(sub_node, astnodes.If) for sub_node in node.body.body):
                        add_vulnerability(
                            "Greedy/Suicidal Function",
                            f"Greedy/Suicidal function detected in function '{node.name.id}' without a condition check.",
                            "greedy_suicidal",
                            "high",
                            get_line_number(node)
                        )

def generate_html_report(vulnerabilities):
    high_vulns = [v for v in vulnerabilities if v['severity'] == 'high']
    medium_vulns = [v for v in vulnerabilities if v['severity'] == 'medium']
    low_vulns = [v for v in vulnerabilities if v['severity'] == 'low']

    html = """
    <html>
    <head>
        <title>Vulnerability Report</title>
        <style>
            table {
                width: 100%;
                border-collapse: collapse;
            }
            th, td {
                padding: 8px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }
            th {
                background-color: #f2f2f2;
            }
            .high {
                background-color: #f8d7da;
            }
            .medium {
                background-color: #fff3cd;
            }
            .low {
                background-color: #d4edda;
            }
        </style>
    </head>
    <body>
        <h1>Vulnerability Report</h1>
        <h2>High Severity</h2>
        <table class="high">
            <tr>
                <th>Name</th>
                <th>Description</th>
                <th>Pattern</th>
                <th>Line</th>
            </tr>
    """
    for vuln in high_vulns:
        html += f"""
            <tr>
                <td>{vuln['name']}</td>
                <td>{vuln['description']}</td>
                <td>{vuln['pattern']}</td>
                <td>{vuln['line']}</td>
            </tr>
        """

    html += """
        </table>
        <h2>Medium Severity</h2>
        <table class="medium">
            <tr>
                <th>Name</th>
                <th>Description</th>
                <th>Pattern</th>
                <th>Line</th>
            </tr>
    """
    for vuln in medium_vulns:
        html += f"""
            <tr>
                <td>{vuln['name']}</td>
                <td>{vuln['description']}</td>
                <td>{vuln['pattern']}</td>
                <td>{vuln['line']}</td>
            </tr>
        """

    html += """
        </table>
        <h2>Low Severity</h2>
        <table class="low">
            <tr>
                <th>Name</th>
                <th>Description</th>
                <th>Pattern</th>
                <th>Line</th>
            </tr>
    """
    for vuln in low_vulns:
        html += f"""
            <tr>
                <td>{vuln['name']}</td>
                <td>{vuln['description']}</td>
                <td>{vuln['pattern']}</td>
                <td>{vuln['line']}</td>
            </tr>
        """

    html += """
        </table>
    </body>
    </html>
    """
    with open("report.html", "w") as file:
        file.write(html)

if __name__ == "__main__":
    lua_file = sys.argv[1]
    with open(lua_file, "r") as file:
        code = file.read()

    analyze_overflow_and_return(code)
    analyze_underflow_and_return(code)
    analyze_return(code)
    check_private_key_exposure(code)
    analyze_reentrancy(code)
    analyze_floating_pragma(code)
    analyze_denial_of_service(code)
    analyze_unchecked_external_calls(code)
    analyze_greedy_suicidal_functions(code)

    generate_html_report(vulnerabilities)
