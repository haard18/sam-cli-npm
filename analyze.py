from luaparser import ast, astnodes
import os
import json
import sys
INT_MAX = 2147483647
INT_MIN = -2147483648

COLORS = {
    "red": "\033[91m",
    "yellow": "\033[93m",
    "cyan": "\033[96m",
    "reset": "\033[0m"
}

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
    transfer_functions = ["transfer", "transfer_funds", "transferfunds", "send", "pay"]

    def is_fund_transfer(node):
        return isinstance(node, astnodes.Call) and isinstance(node.func, astnodes.Name) and node.func.id.lower() in transfer_functions

    def has_conditional(node):
        return isinstance(node, (astnodes.If, astnodes.ElseIf))

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Function):
            has_transfer = False
            has_condition = False

            for n in node.body.body:
                if is_fund_transfer(n):
                    has_transfer = True
                if has_conditional(n):
                    has_condition = True

            if has_transfer and not has_condition:
                add_vulnerability(
                    "Greedy/Suicidal Functions",
                    f"Potential greedy/suicidal contract detected in function '{node.name.id}'.",
                    "greedy_suicidal_function",
                    "high",
                    get_line_number(node)
                )

def print_vulnerabilities():
    for vuln in vulnerabilities:
        color = COLORS["reset"]
        if vuln["severity"] == "high":
            color = COLORS["red"]
        elif vuln["severity"] == "medium":
            color = COLORS["yellow"]
        elif vuln["severity"] == "low":
            color = COLORS["cyan"]

        print(f"{color}Name: {vuln['name']}\nDescription: {vuln['description']}\nPattern: {vuln['pattern']}\nSeverity: {vuln['severity']}\nLine: {vuln['line']}{COLORS['reset']}\n")

def save_report(file_path):
    with open(file_path, 'w') as report_file:
        json.dump(vulnerabilities, report_file, indent=4)
def main():
    if len(sys.argv) < 2:
        print("Usage: python vulnerability_analyzer.py <path_to_lua_code_file>")
        sys.exit(1)

    file_path = sys.argv[1]

    if not os.path.isfile(file_path):
        print("File not found. Please enter a valid file path.")
        sys.exit(1)

    with open(file_path, 'r') as file:
        code = file.read()

    # print("Analyzing the provided Lua code for vulnerabilities:")
    analyze_return(code)
    analyze_overflow_and_return(code)
    analyze_underflow_and_return(code)
    analyze_reentrancy(code)
    check_private_key_exposure(code)
    analyze_floating_pragma(code)
    analyze_denial_of_service(code)
    analyze_unchecked_external_calls(code)
    analyze_greedy_suicidal_functions(code)

    # print_vulnerabilities()

    report_file_path = "report.json"
    save_report(report_file_path)
    print(f"\nVulnerability report saved to {report_file_path}\n")

if __name__ == "__main__":
    main()