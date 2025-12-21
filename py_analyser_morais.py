import ast
import sys
import json
import os
import copy

class SecurityAnalyzer(ast.NodeVisitor):
    def __init__(self, patterns):
        self.patterns = patterns
        # Map to track tainted variables and their history.
        # Format: {'var_name': [ {sourceInfo1}, {sourceInfo2} ] }
        self.tainted_vars = {}
        self.vulnerabilities = []
        self.vuln_counters = {p['vulnerability']: 0 for p in patterns}

    def get_taints_from_node(self, node):
        """
        Inspects a node (RHS of an assignment or function argument) 
        to identify any potential taints.
        """
        taints = []

        # 1. Check if it's a function call (e.g., b())
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            func_name = node.func.id
            for pattern in self.patterns:
                if func_name in pattern['sources']:
                    taints.append({
                        'source': func_name,
                        'line': node.lineno,
                        'vuln': pattern['vulnerability']
                    })

        # 2. Check if it's a variable reference (e.g., c)
        elif isinstance(node, ast.Name):
            var_name = node.id
            
            # A. Propagation: If the variable is already tainted, copy the taint info.
            if var_name in self.tainted_vars:
                taints.extend(self.tainted_vars[var_name])

            # B. Variable as Source: Check if the variable name itself is defined as a source.
            for pattern in self.patterns:
                if var_name in pattern['sources']:
                    taints.append({
                        'source': var_name,
                        'line': node.lineno,
                        'vuln': pattern['vulnerability']
                    })
        
        return taints

    def visit_Assign(self, node):
        # Step 1: Collect all taints from the right-hand side (RHS)
        rhs_taints = self.get_taints_from_node(node.value)

        # Step 2: Apply taints to the left-hand side (LHS) targets
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id

                # Check if the assignment target is a Sink (Vulnerability trigger)
                # Example: d = c (where 'd' is a sink)
                for pattern in self.patterns:
                    if var_name in pattern['sinks']:
                        # Report each taint flow reaching this sink
                        for taint in rhs_taints:
                            if taint['vuln'] == pattern['vulnerability']:
                                self.report_vulnerability(pattern, taint, var_name, node.lineno)

                # Update state (Propagate taint)
                if rhs_taints:
                    self.tainted_vars[var_name] = rhs_taints
                else:
                    # If assigning a clean value (e.g., a = ""), clear previous taints
                    if var_name in self.tainted_vars:
                        del self.tainted_vars[var_name]

        self.generic_visit(node)

    def visit_Call(self, node):
        # Handle function calls that act as sinks (e.g., e(d))
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            
            for pattern in self.patterns:
                if func_name in pattern['sinks']:
                    # Check arguments for taints
                    for arg in node.args:
                        arg_taints = self.get_taints_from_node(arg)
                        for taint in arg_taints:
                            if taint['vuln'] == pattern['vulnerability']:
                                self.report_vulnerability(pattern, taint, func_name, node.lineno)

        self.generic_visit(node)

    def report_vulnerability(self, pattern, source_info, sink_name, sink_line):
        vuln_name = pattern['vulnerability']
        self.vuln_counters[vuln_name] += 1
        vuln_id = f"{vuln_name}_{self.vuln_counters[vuln_name]}"

        vuln_obj = {
            "vulnerability": vuln_id,
            "source": [source_info['source'], source_info['line']],
            "sink": [sink_name, sink_line],
            "flows": [
                ["explicit", []]
            ]
        }
        self.vulnerabilities.append(vuln_obj)

def main():
    if len(sys.argv) != 3:
        print("Usage: python py_analyser.py <slice_path> <patterns_path>")
        sys.exit(1)

    slice_path = sys.argv[1]
    patterns_path = sys.argv[2]

    with open(patterns_path, 'r') as f:
        patterns = json.load(f)
    
    with open(slice_path, 'r') as f:
        code = f.read()

    tree = ast.parse(code)
    analyzer = SecurityAnalyzer(patterns)
    analyzer.visit(tree)

    output_dir = "./output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Construct output filename based on input filename
    slice_filename = os.path.basename(slice_path)
    if slice_filename.endswith('.py'):
        output_filename = slice_filename[:-3] + ".output.json"
    else:
        output_filename = slice_filename + ".output.json"
        
    output_path = os.path.join(output_dir, output_filename)

    with open(output_path, 'w') as f:
        json.dump(analyzer.vulnerabilities, f, indent=4)
    
    print(f"Analysis complete. Output saved to: {output_path}")

if __name__ == "__main__":
    main()
