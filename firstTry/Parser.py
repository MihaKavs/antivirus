from Rule import Rule
import os
from pathlib import Path
import re
    
class Parser:
    def __init__(self, scan_target):
        self.rule_list = []
        for yar_file in Path(scan_target).rglob("*.yar"):
            with open(yar_file, "r") as file:
                file_content = file.read()
                self.rule_list.append(self.rule_compile(file_content))

    def rule_compile(self, rule_text):
        rules = self.find_rule(rule_text)
        compiled_rules = []
        for rule in rules:
            rule_name = rule[0].strip()
            rule_body = rule[1].strip()
            rule_meta = None
            rule_strings = None
            rule_meta_text = self.extract_meta(rule_body)
            rule_strings_text = self.extract_strings(rule_body)
            rule_condition_text = self.extract_condition(rule_body)
            if rule_meta_text is not None:
                rule_meta = self.find_meta(rule_meta_text)
            if rule_strings_text is not None:
                rule_strings = self.find_strings(rule_strings_text)
            compiled_rules.append({
                "name": rule_name,
                "meta": rule_meta,
                "strings": rule_strings,
                "condition": rule_condition_text
            })
        return compiled_rules



    #get ann array of rules
    def find_rule(self, text):
        rules = []
        idx = 0
        in_strings_section = False  
        open_braces = 0  
        
        while idx < len(text):
            # Look for 'rule' keyword
            if text[idx:idx+4] == 'rule':
                rule_name_start = idx + 4
                rule_name_end = text.find('{', rule_name_start)
                rule_name = text[rule_name_start:rule_name_end].strip()

                # Skip invalid rule name or lines with more than 2 words
                if len(rule_name.split()) > 2:
                    idx += 4
                    continue

                rule_body_start = rule_name_end + 1
                rule_body_end = rule_body_start
                open_braces = 1  
                in_strings_section = False 

                while open_braces > 0 and rule_body_end < len(text):
                    if text[rule_body_end:rule_body_end+7] == 'strings':  # Detect strings section
                        in_strings_section = True
                    if text[rule_body_end:rule_body_end+9] == 'condition':  # Detect condition section
                        in_strings_section = False

                    if text[rule_body_end] == '{' and not in_strings_section:
                        open_braces += 1
                    elif text[rule_body_end] == '}' and not in_strings_section:
                        open_braces -= 1

                    rule_body_end += 1

                rule_body = text[rule_body_start:rule_body_end].strip()
                rules.append((rule_name, rule_body))
                idx = rule_body_end
            else:
                idx += 1
        
        return rules

    def extract_meta(self, rule_body):
        # Extract everything between meta: and strings:
        meta_pattern = r'meta\s*:(.*?)strings\s*:'
        match = re.search(meta_pattern, rule_body, re.S)
        return match.group(1).strip() if match else None

    def extract_strings(self, rule_body):
        # Extract everything between strings: and condition:
        strings_pattern = r'strings\s*:\s*(.*?)\s*condition\s*:'
        match = re.search(strings_pattern, rule_body, re.S)
        return match.group(1).strip() if match else None

    def extract_condition(self, rule_body):
        # Extract everything after condition:
        condition_pattern = r'condition\s*:(.*)'
        match = re.search(condition_pattern, rule_body, re.S)
        return match.group(1).strip().strip("\\n").strip("}") if match else None
    
    def find_meta(self, text):
        lines = text.strip().splitlines()
        meta = {}
        in_multiline_comment = False
        
        for line in lines:
            if '/*' in line:
                in_multiline_comment = True
            if '*/' in line:
                in_multiline_comment = False
                continue 

            if in_multiline_comment:
                continue

            if '=' in line:
                key, value = line.split("=", 1)
                meta[key.strip()] = value.strip().strip('"')

        return meta
    
    def find_strings(self, text):
        lines = text.strip().splitlines()
        strings = {}
        current_line = ""
        in_multiline_comment = False

        for line in lines:
            line = line.strip()

            # Skip empty lines
            if not line:
                continue

            # Handle multi-line comments
            if line.startswith("/*"):
                in_multiline_comment = True
            if "*/" in line:
                in_multiline_comment = False
                continue
            if in_multiline_comment:
                continue

            # Skip single-line comments
            if line.startswith("//") or line.startswith("#"):
                continue

            # Accumulate lines for multi-line strings
            if current_line:
                current_line += " " + line
            else:
                current_line = line

            # Check if the current line ends a string definition
            if '"' in current_line and current_line.endswith(("wide", "ascii", "nocase", "fullword")):
                try:
                    key, string_value = current_line.split("=", 1)
                    key = key.strip()
                    string_value = string_value.strip()
                    modifiers = []

                    # Check for modifiers: fullword, nocase, wide, ascii
                    if 'fullword' in string_value:
                        modifiers.append('fullword')
                        string_value = string_value.replace('fullword', '').strip()
                    if 'nocase' in string_value:
                        modifiers.append('nocase')
                        string_value = string_value.replace('nocase', '').strip()
                    if 'wide' in string_value:
                        modifiers.append('wide')
                        string_value = string_value.replace('wide', '').strip()
                    if 'ascii' in string_value:
                        modifiers.append('ascii')
                        string_value = string_value.replace('ascii', '').strip()

                    # Store the string pattern and modifiers
                    strings[key] = {
                        "pattern": string_value.strip('"'),
                        "modifiers": modifiers
                    }

                    current_line = ""  # Reset current line
                except ValueError as e:
                    print(f"Error parsing string line: {current_line}. Error: {e}")
                    current_line = ""  # Reset on error
            else:
                key, string_value = current_line.split("=", 1)
                key = key.strip()
                string_value = string_value.strip()
                strings[key] = {
                        "pattern": string_value.strip('"'),
                        "modifiers": []
                    }


        return strings


            

        