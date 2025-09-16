#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RexPloit - Master Integration Module
This module integrates all components of RexPloit into a unified toolchain
For authorized security testing only
"""

import os
import sys
import importlib
import logging
from rich.console import Console
from rich.panel import Panel

# Set up console
console = Console()

# Module mappings
COMPONENTS = {
    "core": "rexploit",
    "ui": "enhanced_ui",
    "dependencies": "dependency_manager",
    "enhancements": "enhancements",
    "unified": "unified_rexploit"
}

class MasterIntegrator:
    """Integrates all RexPloit components into a unified toolchain"""
    
    def __init__(self):
        self.modules = {}
        self.log_file = os.path.join("logs", "integration.log")
        
        # Ensure logs directory exists
        os.makedirs("logs", exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            filename=self.log_file,
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        self.logger = logging.getLogger("master_integrator")
        
    def load_module(self, module_key):
        """Load a component module by key"""
        if module_key not in COMPONENTS:
            self.logger.error(f"Unknown module key: {module_key}")
            return None
            
        module_name = COMPONENTS[module_key]
        
        try:
            self.logger.info(f"Loading module {module_name}")
            module = importlib.import_module(module_name)
            self.modules[module_key] = module
            return module
        except ImportError as e:
            self.logger.error(f"Failed to import {module_name}: {str(e)}")
            console.print(f"[red]Failed to import {module_name}. Error: {str(e)}[/red]")
            return None
            
    def load_all_modules(self):
        """Load all component modules"""
        console.print("[bold blue]Loading all RexPloit components...[/bold blue]")
        
        success = True
        for key in COMPONENTS:
            module = self.load_module(key)
            if module is None:
                success = False
                
        return success
        
    def validate_integration(self):
        """Validate that all modules integrate correctly"""
        console.print("[bold blue]Validating component integration...[/bold blue]")
        
        # Verify minimum required modules
        required = ["core", "ui", "dependencies"]
        missing = [key for key in required if key not in self.modules]
        
        if missing:
            self.logger.error(f"Missing required modules: {', '.join(missing)}")
            console.print(f"[red]Missing required modules: {', '.join(missing)}[/red]")
            return False
            
        # Validate core module
        try:
            # Check for essential classes in core
            core = self.modules["core"]
            required_classes = ["Logger", "PayloadGenerator", "C2Manager", "Injector", "VulnerabilityScanner", "RexPloitApp"]
            
            for cls_name in required_classes:
                if not hasattr(core, cls_name):
                    self.logger.error(f"Core module missing required class: {cls_name}")
                    console.print(f"[red]Core module missing required class: {cls_name}[/red]")
                    return False
                    
            # Check enhanced UI integration
            ui = self.modules["ui"]
            if not hasattr(ui, "run_enhanced_app"):
                self.logger.error("UI module missing run_enhanced_app function")
                console.print("[red]UI module missing run_enhanced_app function[/red]")
                return False
                
            # Check dependency manager
            dep = self.modules["dependencies"]
            if not hasattr(dep, "DependencyManager"):
                self.logger.error("Dependency module missing DependencyManager class")
                console.print("[red]Dependency module missing DependencyManager class[/red]")
                return False
                
            # Validate unified module
            unified = self.modules.get("unified")
            if unified:
                if not hasattr(unified, "main"):
                    self.logger.error("Unified module missing main function")
                    console.print("[red]Unified module missing main function[/red]")
                    return False
                
            return True
            
        except Exception as e:
            self.logger.error(f"Validation error: {str(e)}")
            console.print(f"[red]Validation error: {str(e)}[/red]")
            return False
            
    def create_workspace_symlinks(self):
        """Create symbolic links to ensure all modules can find each other"""
        console.print("[bold blue]Setting up workspace integration...[/bold blue]")
        
        # Create __init__.py if it doesn't exist
        init_path = os.path.join(os.getcwd(), "__init__.py")
        if not os.path.exists(init_path):
            with open(init_path, "w") as f:
                f.write("# RexPloit Package\n")
            self.logger.info("Created __init__.py file")
                
        return True
        
    def install_missing_dependencies(self):
        """Install any missing dependencies"""
        console.print("[bold blue]Checking for missing dependencies...[/bold blue]")
        
        try:
            # Use dependency manager to install dependencies
            dep = self.modules.get("dependencies")
            if dep and hasattr(dep, "DependencyManager"):
                manager = dep.DependencyManager()
                result = manager.check_all_dependencies(auto_install=True)
                
                if not result:
                    self.logger.warning("Some dependencies could not be installed")
                    console.print("[yellow]Some dependencies could not be installed automatically. Check logs for details.[/yellow]")
                return result
            else:
                self.logger.error("Dependency manager not available")
                console.print("[red]Dependency manager not available[/red]")
                return False
                
        except Exception as e:
            self.logger.error(f"Dependency installation error: {str(e)}")
            console.print(f"[red]Dependency installation error: {str(e)}[/red]")
            return False
            
    def integrate(self):
        """Perform full integration of all components"""
        console.print(Panel("RexPloit Master Integrator", style="bold blue"))
        
        # Load all modules
        if not self.load_all_modules():
            console.print("[red]Failed to load all required modules[/red]")
            return False
            
        # Validate integration
        if not self.validate_integration():
            console.print("[red]Integration validation failed[/red]")
            return False
            
        # Create workspace symlinks
        if not self.create_workspace_symlinks():
            console.print("[yellow]Warning: Failed to set up workspace integration[/yellow]")
            
        # Install missing dependencies
        if not self.install_missing_dependencies():
            console.print("[yellow]Warning: Some dependencies may be missing[/yellow]")
        
        console.print("[bold green]Integration completed successfully[/bold green]")
        console.print("\nYou can now run the unified RexPloit framework with:")
        console.print("[bold cyan]./unified_rexploit.py[/bold cyan]")
        
        return True

# Main entry point
def main():
    integrator = MasterIntegrator()
    success = integrator.integrate()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())