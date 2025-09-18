#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RexPloit Automation Engine
Advanced automation capabilities for penetration testing workflows
For authorized security testing only
"""

import os
import sys
import json
import time
import threading
import subprocess
from datetime import datetime, timedelta
from queue import Queue, PriorityQueue
import random
import hashlib

class AutomationEngine:
    """Advanced automation engine for penetration testing workflows"""
    
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.running = False
        self.workflows = {}
        self.scheduled_tasks = PriorityQueue()
        self.task_history = []
        self.automation_thread = None
        
        # Workflow templates
        self.workflow_templates = {
            "recon_and_exploit": {
                "description": "Comprehensive reconnaissance and exploitation workflow",
                "phases": [
                    {"name": "network_discovery", "priority": 1, "timeout": 300},
                    {"name": "port_scanning", "priority": 2, "timeout": 600},
                    {"name": "service_enumeration", "priority": 3, "timeout": 900},
                    {"name": "vulnerability_scanning", "priority": 4, "timeout": 1800},
                    {"name": "payload_generation", "priority": 5, "timeout": 300},
                    {"name": "exploitation", "priority": 6, "timeout": 1200},
                    {"name": "post_exploitation", "priority": 7, "timeout": 1800},
                    {"name": "persistence", "priority": 8, "timeout": 600},
                    {"name": "data_exfiltration", "priority": 9, "timeout": 900},
                    {"name": "cleanup", "priority": 10, "timeout": 300}
                ]
            },
            
            "payload_fuzzing": {
                "description": "Automated payload fuzzing and testing workflow",
                "phases": [
                    {"name": "baseline_payload_generation", "priority": 1, "timeout": 120},
                    {"name": "fuzzing_variants_creation", "priority": 2, "timeout": 600},
                    {"name": "injection_testing", "priority": 3, "timeout": 1800},
                    {"name": "evasion_testing", "priority": 4, "timeout": 900},
                    {"name": "persistence_testing", "priority": 5, "timeout": 600},
                    {"name": "cleanup_testing", "priority": 6, "timeout": 300}
                ]
            },
            
            "c2_automation": {
                "description": "Automated C2 framework management and operations",
                "phases": [
                    {"name": "c2_setup", "priority": 1, "timeout": 180},
                    {"name": "listener_configuration", "priority": 2, "timeout": 120},
                    {"name": "payload_deployment", "priority": 3, "timeout": 600},
                    {"name": "session_management", "priority": 4, "timeout": 3600},
                    {"name": "command_automation", "priority": 5, "timeout": 1800},
                    {"name": "data_collection", "priority": 6, "timeout": 900},
                    {"name": "session_cleanup", "priority": 7, "timeout": 300}
                ]
            },
            
            "stealth_operation": {
                "description": "Stealth-focused automated penetration testing",
                "phases": [
                    {"name": "passive_reconnaissance", "priority": 1, "timeout": 1800},
                    {"name": "low_profile_scanning", "priority": 2, "timeout": 3600},
                    {"name": "stealth_payload_generation", "priority": 3, "timeout": 300},
                    {"name": "covert_deployment", "priority": 4, "timeout": 1200},
                    {"name": "silent_persistence", "priority": 5, "timeout": 600},
                    {"name": "stealthy_exfiltration", "priority": 6, "timeout": 1800},
                    {"name": "trace_cleanup", "priority": 7, "timeout": 600}
                ]
            }
        }
        
        # Task implementations
        self.task_implementations = {
            "network_discovery": self._execute_network_discovery,
            "port_scanning": self._execute_port_scanning,
            "service_enumeration": self._execute_service_enumeration,
            "vulnerability_scanning": self._execute_vulnerability_scanning,
            "payload_generation": self._execute_payload_generation,
            "exploitation": self._execute_exploitation,
            "post_exploitation": self._execute_post_exploitation,
            "persistence": self._execute_persistence,
            "data_exfiltration": self._execute_data_exfiltration,
            "cleanup": self._execute_cleanup,
            "baseline_payload_generation": self._execute_baseline_payload_generation,
            "fuzzing_variants_creation": self._execute_fuzzing_variants_creation,
            "injection_testing": self._execute_injection_testing,
            "evasion_testing": self._execute_evasion_testing,
            "persistence_testing": self._execute_persistence_testing,
            "cleanup_testing": self._execute_cleanup_testing,
            "c2_setup": self._execute_c2_setup,
            "listener_configuration": self._execute_listener_configuration,
            "payload_deployment": self._execute_payload_deployment,
            "session_management": self._execute_session_management,
            "command_automation": self._execute_command_automation,
            "data_collection": self._execute_data_collection,
            "session_cleanup": self._execute_session_cleanup,
            "passive_reconnaissance": self._execute_passive_reconnaissance,
            "low_profile_scanning": self._execute_low_profile_scanning,
            "stealth_payload_generation": self._execute_stealth_payload_generation,
            "covert_deployment": self._execute_covert_deployment,
            "silent_persistence": self._execute_silent_persistence,
            "stealthy_exfiltration": self._execute_stealthy_exfiltration,
            "trace_cleanup": self._execute_trace_cleanup
        }

    def start_automation_engine(self):
        """Start the automation engine"""
        if self.running:
            return {"success": False, "error": "Automation engine already running"}
        
        self.running = True
        self.automation_thread = threading.Thread(target=self._automation_worker, daemon=True)
        self.automation_thread.start()
        
        self.logger.info("Automation engine started successfully")
        return {"success": True, "message": "Automation engine started"}

    def stop_automation_engine(self):
        """Stop the automation engine"""
        self.running = False
        if self.automation_thread and self.automation_thread.is_alive():
            self.automation_thread.join(timeout=5)
        
        self.logger.info("Automation engine stopped")
        return {"success": True, "message": "Automation engine stopped"}

    def create_workflow(self, workflow_name, template_name, targets, parameters=None):
        """Create a new automated workflow"""
        try:
            if template_name not in self.workflow_templates:
                return {"success": False, "error": f"Unknown workflow template: {template_name}"}
            
            template = self.workflow_templates[template_name]
            parameters = parameters or {}
            
            workflow = {
                "id": workflow_name,
                "template": template_name,
                "description": template["description"],
                "targets": targets if isinstance(targets, list) else [targets],
                "parameters": parameters,
                "created": datetime.now().isoformat(),
                "status": "created",
                "phases": template["phases"].copy(),
                "current_phase": None,
                "results": {},
                "start_time": None,
                "end_time": None
            }
            
            self.workflows[workflow_name] = workflow
            self.logger.info(f"Workflow '{workflow_name}' created using template '{template_name}'")
            
            return {"success": True, "workflow": workflow}
            
        except Exception as e:
            self.logger.error(f"Failed to create workflow: {str(e)}")
            return {"success": False, "error": str(e)}

    def start_workflow(self, workflow_name, delay_seconds=0):
        """Start an automated workflow"""
        try:
            if workflow_name not in self.workflows:
                return {"success": False, "error": f"Workflow '{workflow_name}' not found"}
            
            workflow = self.workflows[workflow_name]
            
            if workflow["status"] != "created":
                return {"success": False, "error": f"Workflow is in '{workflow['status']}' state"}
            
            # Schedule workflow phases
            schedule_time = datetime.now() + timedelta(seconds=delay_seconds)
            
            for i, phase in enumerate(workflow["phases"]):
                task = {
                    "workflow_id": workflow_name,
                    "phase_name": phase["name"],
                    "phase_index": i,
                    "priority": phase["priority"],
                    "timeout": phase["timeout"],
                    "scheduled_time": schedule_time + timedelta(seconds=i * 5),  # 5-second gaps between phases
                    "parameters": workflow["parameters"],
                    "targets": workflow["targets"]
                }
                
                # Use priority queue (lower number = higher priority)
                self.scheduled_tasks.put((task["priority"], time.time(), task))
            
            workflow["status"] = "scheduled"
            workflow["start_time"] = schedule_time.isoformat()
            
            self.logger.info(f"Workflow '{workflow_name}' scheduled to start at {schedule_time}")
            
            return {"success": True, "message": f"Workflow scheduled", "start_time": schedule_time.isoformat()}
            
        except Exception as e:
            self.logger.error(f"Failed to start workflow: {str(e)}")
            return {"success": False, "error": str(e)}

    def _automation_worker(self):
        """Main automation worker thread"""
        while self.running:
            try:
                # Check for scheduled tasks
                current_time = datetime.now()
                
                # Process due tasks
                tasks_to_process = []
                
                # Get all tasks that are due
                while not self.scheduled_tasks.empty():
                    priority, timestamp, task = self.scheduled_tasks.get()
                    
                    if datetime.fromisoformat(task["scheduled_time"]) <= current_time:
                        tasks_to_process.append(task)
                    else:
                        # Put it back if not due yet
                        self.scheduled_tasks.put((priority, timestamp, task))
                        break
                
                # Execute due tasks
                for task in tasks_to_process:
                    self._execute_task(task)
                
                # Sleep for a short interval
                time.sleep(1)
                
            except Exception as e:
                self.logger.error(f"Automation worker error: {str(e)}")
                time.sleep(5)

    def _execute_task(self, task):
        """Execute a single automation task"""
        try:
            workflow_id = task["workflow_id"]
            phase_name = task["phase_name"]
            
            self.logger.info(f"Executing task: {workflow_id}.{phase_name}")
            
            # Update workflow status
            if workflow_id in self.workflows:
                workflow = self.workflows[workflow_id]
                workflow["current_phase"] = phase_name
                workflow["status"] = "running"
            
            # Execute the task
            if phase_name in self.task_implementations:
                start_time = datetime.now()
                
                try:
                    result = self.task_implementations[phase_name](task)
                    execution_time = (datetime.now() - start_time).total_seconds()
                    
                    # Record result
                    task_record = {
                        "workflow_id": workflow_id,
                        "phase_name": phase_name,
                        "start_time": start_time.isoformat(),
                        "execution_time": execution_time,
                        "result": result,
                        "success": result.get("success", False)
                    }
                    
                    self.task_history.append(task_record)
                    
                    # Update workflow results
                    if workflow_id in self.workflows:
                        self.workflows[workflow_id]["results"][phase_name] = task_record
                    
                    self.logger.info(f"Task completed: {workflow_id}.{phase_name} - Success: {result.get('success', False)}")
                    
                except Exception as e:
                    self.logger.error(f"Task execution failed: {workflow_id}.{phase_name} - {str(e)}")
                    
                    # Record failure
                    task_record = {
                        "workflow_id": workflow_id,
                        "phase_name": phase_name,
                        "start_time": start_time.isoformat(),
                        "execution_time": (datetime.now() - start_time).total_seconds(),
                        "result": {"success": False, "error": str(e)},
                        "success": False
                    }
                    
                    self.task_history.append(task_record)
                    
                    if workflow_id in self.workflows:
                        self.workflows[workflow_id]["results"][phase_name] = task_record
            
            else:
                self.logger.warning(f"No implementation found for task: {phase_name}")
            
            # Check if workflow is complete
            if workflow_id in self.workflows:
                self._check_workflow_completion(workflow_id)
                
        except Exception as e:
            self.logger.error(f"Task execution error: {str(e)}")

    def _check_workflow_completion(self, workflow_id):
        """Check if workflow is complete and update status"""
        try:
            workflow = self.workflows[workflow_id]
            total_phases = len(workflow["phases"])
            completed_phases = len(workflow["results"])
            
            if completed_phases >= total_phases:
                workflow["status"] = "completed"
                workflow["end_time"] = datetime.now().isoformat()
                workflow["current_phase"] = None
                
                # Calculate success rate
                successful_phases = sum(1 for result in workflow["results"].values() if result.get("success", False))
                workflow["success_rate"] = successful_phases / total_phases
                
                self.logger.info(f"Workflow '{workflow_id}' completed with {successful_phases}/{total_phases} successful phases")
                
        except Exception as e:
            self.logger.error(f"Error checking workflow completion: {str(e)}")

    # Task implementation methods
    def _execute_network_discovery(self, task):
        """Execute network discovery phase"""
        self.logger.info("Executing network discovery")
        time.sleep(random.uniform(5, 15))  # Simulate execution time
        
        discovered_hosts = []
        for target in task["targets"]:
            # Simulate host discovery
            base_ip = ".".join(target.split(".")[:-1]) + "."
            for i in range(1, random.randint(5, 20)):
                discovered_hosts.append(f"{base_ip}{i}")
        
        return {
            "success": True,
            "discovered_hosts": discovered_hosts,
            "message": f"Discovered {len(discovered_hosts)} hosts"
        }

    def _execute_port_scanning(self, task):
        """Execute port scanning phase"""
        self.logger.info("Executing port scanning")
        time.sleep(random.uniform(10, 30))
        
        # Simulate port scan results
        common_ports = [22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306]
        open_ports = {}
        
        for target in task["targets"]:
            target_ports = random.sample(common_ports, random.randint(2, 8))
            open_ports[target] = target_ports
        
        return {
            "success": True,
            "open_ports": open_ports,
            "message": f"Scanned {len(task['targets'])} targets"
        }

    def _execute_service_enumeration(self, task):
        """Execute service enumeration phase"""
        self.logger.info("Executing service enumeration")
        time.sleep(random.uniform(15, 45))
        
        services = {
            22: "SSH",
            80: "HTTP",
            443: "HTTPS", 
            3306: "MySQL",
            5432: "PostgreSQL"
        }
        
        return {
            "success": True,
            "services_identified": services,
            "message": "Service enumeration completed"
        }

    def _execute_vulnerability_scanning(self, task):
        """Execute vulnerability scanning phase"""
        self.logger.info("Executing vulnerability scanning")
        time.sleep(random.uniform(30, 90))
        
        vulnerabilities = [
            {"cve": "CVE-2021-44228", "severity": "Critical", "service": "Log4j"},
            {"cve": "CVE-2022-30190", "severity": "High", "service": "Microsoft Office"},
            {"cve": "CVE-2021-34527", "severity": "High", "service": "Print Spooler"}
        ]
        
        found_vulns = random.sample(vulnerabilities, random.randint(0, len(vulnerabilities)))
        
        return {
            "success": True,
            "vulnerabilities": found_vulns,
            "message": f"Found {len(found_vulns)} vulnerabilities"
        }

    def _execute_payload_generation(self, task):
        """Execute payload generation phase"""
        self.logger.info("Executing payload generation")
        time.sleep(random.uniform(5, 15))
        
        payload_types = ["python", "powershell", "bash", "php"]
        generated_payloads = []
        
        for payload_type in payload_types:
            payload_info = {
                "type": payload_type,
                "file": f"payload_{payload_type}_{int(time.time())}.{payload_type[:2]}",
                "size": random.randint(1024, 8192),
                "obfuscated": random.choice([True, False])
            }
            generated_payloads.append(payload_info)
        
        return {
            "success": True,
            "payloads": generated_payloads,
            "message": f"Generated {len(generated_payloads)} payloads"
        }

    def _execute_exploitation(self, task):
        """Execute exploitation phase"""
        self.logger.info("Executing exploitation")
        time.sleep(random.uniform(20, 60))
        
        exploitation_results = []
        for target in task["targets"]:
            success = random.choice([True, False])
            result = {
                "target": target,
                "success": success,
                "method": random.choice(["ssh_bruteforce", "web_exploit", "smb_exploit"]),
                "access_level": random.choice(["user", "admin", "system"]) if success else None
            }
            exploitation_results.append(result)
        
        successful_exploits = [r for r in exploitation_results if r["success"]]
        
        return {
            "success": len(successful_exploits) > 0,
            "exploitation_results": exploitation_results,
            "successful_compromises": len(successful_exploits),
            "message": f"Successfully compromised {len(successful_exploits)}/{len(task['targets'])} targets"
        }

    def _execute_post_exploitation(self, task):
        """Execute post-exploitation phase"""
        self.logger.info("Executing post-exploitation")
        time.sleep(random.uniform(30, 90))
        
        post_exploit_actions = [
            "privilege_escalation",
            "credential_harvesting", 
            "lateral_movement",
            "data_discovery",
            "network_mapping"
        ]
        
        completed_actions = random.sample(post_exploit_actions, random.randint(2, len(post_exploit_actions)))
        
        return {
            "success": True,
            "completed_actions": completed_actions,
            "message": f"Completed {len(completed_actions)} post-exploitation actions"
        }

    def _execute_persistence(self, task):
        """Execute persistence establishment phase"""
        self.logger.info("Executing persistence establishment")
        time.sleep(random.uniform(10, 30))
        
        persistence_methods = [
            "registry_key",
            "scheduled_task",
            "service_installation", 
            "startup_folder",
            "dll_hijacking"
        ]
        
        established_persistence = random.sample(persistence_methods, random.randint(1, 3))
        
        return {
            "success": True,
            "persistence_methods": established_persistence,
            "message": f"Established {len(established_persistence)} persistence mechanisms"
        }

    def _execute_data_exfiltration(self, task):
        """Execute data exfiltration phase"""
        self.logger.info("Executing data exfiltration")
        time.sleep(random.uniform(20, 60))
        
        exfiltrated_data = {
            "credentials": random.randint(10, 100),
            "documents": random.randint(50, 500),
            "database_records": random.randint(100, 10000),
            "network_configs": random.randint(5, 50)
        }
        
        return {
            "success": True,
            "exfiltrated_data": exfiltrated_data,
            "message": "Data exfiltration completed successfully"
        }

    def _execute_cleanup(self, task):
        """Execute cleanup phase"""
        self.logger.info("Executing cleanup")
        time.sleep(random.uniform(5, 15))
        
        cleanup_actions = [
            "log_clearing",
            "artifact_removal",
            "connection_termination",
            "backdoor_removal"
        ]
        
        return {
            "success": True,
            "cleanup_actions": cleanup_actions,
            "message": "Cleanup completed successfully"
        }

    # Additional task implementations for other workflow types
    def _execute_baseline_payload_generation(self, task):
        """Execute baseline payload generation for fuzzing"""
        time.sleep(random.uniform(2, 8))
        return {"success": True, "baseline_payload": "baseline_payload.py", "message": "Baseline payload generated"}

    def _execute_fuzzing_variants_creation(self, task):
        """Execute fuzzing variants creation"""
        time.sleep(random.uniform(10, 30))
        return {"success": True, "variants_created": random.randint(50, 200), "message": "Fuzzing variants created"}

    def _execute_injection_testing(self, task):
        """Execute injection testing"""
        time.sleep(random.uniform(30, 90))
        return {"success": True, "injections_tested": random.randint(10, 50), "message": "Injection testing completed"}

    def _execute_evasion_testing(self, task):
        """Execute evasion testing"""
        time.sleep(random.uniform(15, 45))
        return {"success": True, "evasion_rate": random.uniform(0.6, 0.95), "message": "Evasion testing completed"}

    def _execute_persistence_testing(self, task):
        """Execute persistence testing"""
        time.sleep(random.uniform(10, 30))
        return {"success": True, "persistence_success": random.choice([True, False]), "message": "Persistence testing completed"}

    def _execute_cleanup_testing(self, task):
        """Execute cleanup testing"""
        time.sleep(random.uniform(5, 15))
        return {"success": True, "cleanup_verified": True, "message": "Cleanup testing completed"}

    def _execute_c2_setup(self, task):
        """Execute C2 setup"""
        time.sleep(random.uniform(5, 20))
        return {"success": True, "c2_framework": "villain", "message": "C2 framework started"}

    def _execute_listener_configuration(self, task):
        """Execute listener configuration"""
        time.sleep(random.uniform(2, 10))
        return {"success": True, "listeners": ["tcp:4444", "http:8080"], "message": "Listeners configured"}

    def _execute_payload_deployment(self, task):
        """Execute payload deployment"""
        time.sleep(random.uniform(10, 30))
        return {"success": True, "deployed_payloads": random.randint(1, 5), "message": "Payloads deployed"}

    def _execute_session_management(self, task):
        """Execute session management"""
        time.sleep(random.uniform(5, 15))
        return {"success": True, "active_sessions": random.randint(0, 10), "message": "Sessions managed"}

    def _execute_command_automation(self, task):
        """Execute command automation"""
        time.sleep(random.uniform(20, 60))
        return {"success": True, "commands_executed": random.randint(10, 50), "message": "Commands automated"}

    def _execute_data_collection(self, task):
        """Execute data collection"""
        time.sleep(random.uniform(15, 45))
        return {"success": True, "data_collected": f"{random.randint(1, 100)}MB", "message": "Data collected"}

    def _execute_session_cleanup(self, task):
        """Execute session cleanup"""
        time.sleep(random.uniform(5, 15))
        return {"success": True, "sessions_cleaned": random.randint(1, 10), "message": "Sessions cleaned up"}

    def _execute_passive_reconnaissance(self, task):
        """Execute passive reconnaissance"""
        time.sleep(random.uniform(30, 120))
        return {"success": True, "intelligence_gathered": "extensive", "message": "Passive recon completed"}

    def _execute_low_profile_scanning(self, task):
        """Execute low profile scanning"""
        time.sleep(random.uniform(60, 180))
        return {"success": True, "stealth_maintained": True, "message": "Low profile scan completed"}

    def _execute_stealth_payload_generation(self, task):
        """Execute stealth payload generation"""
        time.sleep(random.uniform(10, 20))
        return {"success": True, "stealth_payload": "stealth_payload.py", "message": "Stealth payload generated"}

    def _execute_covert_deployment(self, task):
        """Execute covert deployment"""
        time.sleep(random.uniform(20, 40))
        return {"success": True, "covert_channels": ["dns", "icmp"], "message": "Covert deployment completed"}

    def _execute_silent_persistence(self, task):
        """Execute silent persistence"""
        time.sleep(random.uniform(10, 25))
        return {"success": True, "silent_mechanisms": 2, "message": "Silent persistence established"}

    def _execute_stealthy_exfiltration(self, task):
        """Execute stealthy exfiltration"""
        time.sleep(random.uniform(30, 90))
        return {"success": True, "exfiltration_method": "steganography", "message": "Stealthy exfiltration completed"}

    def _execute_trace_cleanup(self, task):
        """Execute trace cleanup"""
        time.sleep(random.uniform(10, 30))
        return {"success": True, "traces_removed": True, "message": "All traces cleaned"}

    def get_automation_status(self):
        """Get current automation status"""
        return {
            "engine_running": self.running,
            "active_workflows": len([w for w in self.workflows.values() if w["status"] in ["scheduled", "running"]]),
            "completed_workflows": len([w for w in self.workflows.values() if w["status"] == "completed"]),
            "scheduled_tasks": self.scheduled_tasks.qsize(),
            "total_workflows": len(self.workflows),
            "task_history_count": len(self.task_history)
        }

    def get_workflow_status(self, workflow_name):
        """Get status of specific workflow"""
        if workflow_name not in self.workflows:
            return {"error": "Workflow not found"}
        
        return self.workflows[workflow_name]

    def list_workflows(self):
        """List all workflows"""
        return list(self.workflows.values())

    def cancel_workflow(self, workflow_name):
        """Cancel a workflow"""
        if workflow_name not in self.workflows:
            return {"success": False, "error": "Workflow not found"}
        
        workflow = self.workflows[workflow_name]
        if workflow["status"] in ["completed", "cancelled"]:
            return {"success": False, "error": f"Cannot cancel workflow in '{workflow['status']}' state"}
        
        workflow["status"] = "cancelled"
        workflow["end_time"] = datetime.now().isoformat()
        
        self.logger.info(f"Workflow '{workflow_name}' cancelled")
        return {"success": True, "message": "Workflow cancelled"}

    def get_workflow_templates(self):
        """Get available workflow templates"""
        return {name: template["description"] for name, template in self.workflow_templates.items()}

    def generate_automation_report(self, workflow_name=None):
        """Generate automation report"""
        if workflow_name:
            if workflow_name not in self.workflows:
                return {"error": "Workflow not found"}
            workflows_to_report = [self.workflows[workflow_name]]
        else:
            workflows_to_report = list(self.workflows.values())
        
        report = {
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_workflows": len(workflows_to_report),
                "completed_workflows": len([w for w in workflows_to_report if w["status"] == "completed"]),
                "successful_workflows": len([w for w in workflows_to_report if w.get("success_rate", 0) > 0.7]),
                "total_tasks_executed": sum(len(w.get("results", {})) for w in workflows_to_report)
            },
            "workflows": workflows_to_report,
            "engine_status": self.get_automation_status()
        }
        
        return report