from Parser import Parser
import re
import os

class Compiler:
    def __init__(self, rule_path, file_path):
        self.rule_path = rule_path
        self.file_path = file_path
        self.parser = Parser(rule_path)
        self.parsed_rules = self.parser.rule_list
        self.broken_rule_name = ""

    def get_matches(self, text, rules):
        matched_identifiers = {}
        for rule in rules:
            # Iterate over the list of strings
            for identifier, string_data in rule.get("strings", {}).items():
                pattern = string_data.get("pattern")
                modifiers = string_data.get("modifiers", [])

                # Apply modifiers to match patterns (e.g., wide, nocase)
                flags = 0
                if "nocase" in modifiers:
                    flags |= re.IGNORECASE

                if pattern.startswith("/") and pattern.endswith("/"):
                    # Regex pattern
                    regex = re.compile(pattern[1:-1], flags)
                    if regex.search(text):
                        matched_identifiers[identifier] = True
                else:
                    # Simple string pattern
                    encoded_patterns = [pattern.encode("utf-16-le")] if "wide" in modifiers else [pattern.encode()]
                    if "ascii" in modifiers:
                        encoded_patterns.append(pattern.encode("ascii"))

                    for encoded_pattern in encoded_patterns:
                        if encoded_pattern in text:
                            matched_identifiers[identifier] = True

            return matched_identifiers



    def is_broken(self, identifiers, rules, text):
        if identifiers == None:
            return False
        if len(identifiers) == 0:
            return False
        for rule in rules:
            condition = rule["condition"]
            condition = condition.replace("\n", "")
            rule_strings = list(rule.get("strings", {}).keys())
            try:
                if self.eval_condition(condition, identifiers, rule_strings, text):
                    self.broken_rule_name = rule["name"]
                    return True
            except Exception as e:
                print(f"Error evaluating condition: {condition}. Error: {e}")
                return False

    def rule_match(self, text, rule):
        identifiers = self.get_matches(text, rule)
        if self.is_broken(identifiers, rule, text):
            return True
        return False

    def scan_file(self, file_path):
        if os.path.isdir(file_path):
            for root, _, files in os.walk(file_path):
                for file in files:
                    file_full_path = os.path.join(root, file)
                    self.scan_file(file_full_path)  # Recursive call for each file
        else:
            if not os.path.isfile(file_path):
                return

            with open(file_path, 'rb') as file:
                data = file.read()

            for rule in self.parsed_rules:
                if self.rule_match(data, rule):
                    print(file_path + " broke " + self.broken_rule_name)


    def eval_condition(self, cond, identifiers, rule_strings, text):
        # Preprocess the condition string
        cond = self.handle_at_operator(cond, identifiers)
        cond = self.handle_uint16_operator(cond, text)
        cond = self.handle_filesize_operator(cond, text)
        cond = self.handle_all_of_operator(cond, identifiers)
        cond = self.handle_all_of_them_operator(cond, identifiers, rule_strings)
        cond = self.handle_any_of_them_operator(cond, identifiers, rule_strings)
        cond = self.handle_n_of_operator(cond, identifiers)
        cond = self.handle_n_of_them_operator(cond, identifiers, rule_strings)
        cond = self.handle_identifier(cond, identifiers, rule_strings)

        # Replace remaining identifiers with their truth values
        for key in identifiers:
            if isinstance(cond, str):  # Ensure cond is a string
                cond = cond.replace(f"${key}", "True")
        
        # Replace any remaining unmatched identifiers with False
        if isinstance(cond, str):  # Ensure cond is still a string
            cond = re.sub(r"\$[a-zA-Z_][a-zA-Z0-9_]*", "False", cond)
        
        # Now eval the condition string
        try:
            if isinstance(cond, str):
                return eval(cond)
            else:
                return cond
        except Exception as e:
            print(f"Error evaluating condition: {cond}. Error: {e}")
            return False

    def handle_at_operator(self, cond, identifiers):
        at_pattern = re.compile(r"\$(\w+)\s+at\s+(\d+)")
        for match in at_pattern.finditer(cond):
            identifier, position = match.groups()
            position = int(position)
            if identifier in identifiers:
                variable_matches = identifiers[identifier]
                cond = cond.replace(match.group(0), str(any(m.start() == position for m in variable_matches)))
            else:
                cond = cond.replace(match.group(0), "False")
        return cond

    def handle_uint16_operator(self, cond, text):
        uint16_pattern = re.compile(r"uint16\((\d+)\)")  # Match uint16(offset)
        
        for match in uint16_pattern.finditer(cond):
            offset = int(match.group(1))  # Get the offset as an integer
            uint16_value = self.uint16(offset, text)  # Call uint16() function
            
            # Ensure uint16_value is not None (or set it to 0 if out-of-bounds)
            if uint16_value is None:
                uint16_value = 0  # Default to 0 if out of bounds
            
            # Replace uint16(offset) with the value
            cond = cond.replace(match.group(0), str(uint16_value)) 
        
        return cond

    def handle_filesize_operator(self, cond, text):
        filesize = len(text) 
        filesize_unit_pattern = re.compile(r"filesize\s*(>|<|>=|<=|==|!=)\s*(\d+)(KB|MB|B)")
        for match in filesize_unit_pattern.finditer(cond):
            operator = match.group(1)
            value = int(match.group(2))
            unit = match.group(3)
            if unit == "KB":
                value *= 1024
            elif unit == "MB":
                value *= 1024 * 1024
            cond = cond.replace(match.group(0), f"{filesize} {operator} {value}")
        return cond

    def handle_all_of_operator(self, cond, identifiers):
        all_of_pattern = re.compile(r"all of \(\$(\w+)\*\)")
        for match in all_of_pattern.finditer(cond):
            prefix = match.group(1)
            matching_vars = [key for key in identifiers if key.startswith(prefix)]
            all_of_result = all(f"${var}" in identifiers for var in matching_vars)
            cond = cond.replace(match.group(0), str(all_of_result))
        return cond

    def handle_all_of_them_operator(self, cond, identifiers, rule_strings):
        all_of_them_pattern = re.compile(r"all of them")
        for match in all_of_them_pattern.finditer(cond):
            all_of_them_result = all(f"${identifier}" in identifiers for identifier in rule_strings)
            cond = cond.replace(match.group(0), str(all_of_them_result))
        return cond

    def handle_any_of_them_operator(self, cond, identifiers, rule_strings):
        any_of_them_pattern = re.compile(r"any of them")
        for match in any_of_them_pattern.finditer(cond):
            any_of_them_result = any(f"${identifier}" in identifiers for identifier in rule_strings)
            cond = cond.replace(match.group(0), str(any_of_them_result))
        return cond

    def handle_n_of_operator(self, cond, identifiers):
        n_of_pattern = re.compile(r"(\d+)\s+of\s*\(([\$\w\*\s,]+)\)")
        for match in n_of_pattern.finditer(cond):
            n = int(match.group(1))
            variable_set = match.group(2).strip()
            variable_set = [var.strip() for var in variable_set.split(",")]
            match_count = 0
            for var in variable_set:
                if "*" in var:
                    prefix = var.replace("$", "").replace("*", "").strip()
                    matching_vars = [key for key in identifiers if key.startswith(prefix)]
                    match_count += sum(1 for var in matching_vars if f"${var}" in identifiers)
                else:
                    if var in identifiers:
                        match_count += 1
            n_of_result = match_count >= n
            cond = cond.replace(match.group(0), str(n_of_result))
        return cond

    def handle_n_of_them_operator(self, cond, identifiers, rule_strings):
        n_of_them_pattern = re.compile(r"(\d+)\s+of\s+them")
        for match in n_of_them_pattern.finditer(cond):
            n = int(match.group(1))
            matching_count = sum(1 for identifier in rule_strings if f"${identifier}" in identifiers)
            n_of_them_result = matching_count >= n
            cond = cond.replace(match.group(0), str(n_of_them_result))
        return cond
    
    def uint16(self, offset, data):
        # Preveri, ali je offset v mejah podatkov
        if offset + 2 > len(data):
            return None  # Out of bounds

        # Preveri, ali so podatki validni bajtni niz
        if not isinstance(data, bytes):
            raise ValueError("Data must be of type 'bytes'.")

        # Preberi 2 bajta in jih pretvori v little-endian 16-bit integer
        uint16_value = int.from_bytes(data[offset:offset + 2], byteorder='little', signed=False)

        return uint16_value
    
    # if identifier matches rule broke
    def handle_identifier(self, cond, identifiers, rule_strings):
        # Check if the identifier is part of a condition involving other identifiers
        for rule_string in rule_strings:
            # Example: "$str1" or "$mz" in conditions
            identifier_pattern = re.compile(rf"\{rule_string}")
            
            # If we find the rule_string, check the context around it
            if identifier_pattern.search(cond):
                # Check if it is part of an "all of", "any of", or "n of" condition
                if "all of" in cond or "any of" in cond or "of" in cond:
                    return f"${rule_string}" in cond  # Only consider true if it's in the context
                else:
                    return True  # It's a direct match for the condition

        return False
