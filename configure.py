from termcolor import cprint
import os
import subprocess
import paramiko
import time
from abc import ABC, abstractmethod

VBOXMANAGE_EXE = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
ISE_VM_NAME = "ISE_14.7_VIRTUAL_MACHINE"
ISE_VM_HOSTNAME = "ise"
ISE_VM_USER = "ise"
ISE_VM_PASSWORD = "xilinx"

# Initialize start time for logging
start_time = time.time()

def log(message, color="white", level="INFO"):
    """Log message with elapsed time since script start."""
    elapsed = time.time() - start_time
    timestamp = f"[{elapsed:.3f}]"
    cprint(f"{timestamp} {level}: {message}", color)

def log_job_start(job_name):
    """Log the start of a job."""
    log(f"Start job: {job_name}", "cyan", "JOB")

def log_job_success(job_name):
    """Log successful completion of a job."""
    log(f"Job succeeded: {job_name}", "green", "JOB")

def log_job_failed(job_name, error=None):
    """Log failed completion of a job."""
    error_msg = f" - {error}" if error else ""
    log(f"Job failed: {job_name}{error_msg}", "red", "JOB")

class Context:
    """Shared context for commands to store and retrieve data."""
    def __init__(self):
        self.data = {}
    
    def set(self, key, value):
        self.data[key] = value
    
    def get(self, key, default=None):
        return self.data.get(key, default)

class Command(ABC):
    """Abstract base class for all commands."""
    
    def __init__(self, name):
        self.name = name
    
    @abstractmethod
    def execute(self, context: Context):
        """Execute the command with the given context."""
        pass

class CommandExecutor:
    """Executes commands with proper logging and error handling."""
    
    def execute_command(self, command: Command, context: Context):
        """Execute a single command."""
        log_job_start(command.name)
        try:
            result = command.execute(context)
            log_job_success(command.name)
            return result
        except Exception as e:
            log_job_failed(command.name, str(e))
            raise
    
    def execute_commands(self, commands: list, context: Context):
        """Execute a list of commands in sequence."""
        for command in commands:
            self.execute_command(command, context)

class CheckVBoxManageCommand(Command):
    """Command to check if VBoxManage is available."""
    
    def __init__(self):
        super().__init__("Check VBoxManage availability")
    
    def execute(self, context: Context):
        if os.path.exists(VBOXMANAGE_EXE):
            log(f"VBoxManage found at: {VBOXMANAGE_EXE}", "green")
            context.set("vboxmanage_path", VBOXMANAGE_EXE)
        else:
            error_msg = f"VBoxManage not found at: {VBOXMANAGE_EXE}"
            log(error_msg, "red")
            raise FileNotFoundError(error_msg)

class ListVMsCommand(Command):
    """Command to list VirtualBox VMs."""
    
    def __init__(self, running_only=False):
        name = "List running VMs" if running_only else "List all VMs"
        super().__init__(name)
        self.running_only = running_only
    
    def execute(self, context: Context):
        cmd_arg = "runningvms" if self.running_only else "vms"
        result = subprocess.run([VBOXMANAGE_EXE, "list", cmd_arg], 
                                capture_output=True, text=True, check=True)
        
        if result.stdout.strip():
            log_type = "Running VMs:" if self.running_only else "All VMs:"
            log(log_type, "cyan")
            vm_list = []
            for line in result.stdout.strip().split('\n'):
                vm_name = line.split('"')[1] if '"' in line else line.split()[0]
                vm_list.append(vm_name)
                log(f"  {line}", "yellow")
            
            key = "running_vms" if self.running_only else "all_vms"
            context.set(key, vm_list)
            return vm_list
        else:
            # Handle empty results gracefully
            if self.running_only:
                log("No running VMs found", "yellow")
                context.set("running_vms", [])
                return []
            else:
                error_msg = "No VMs found"
                raise RuntimeError(error_msg)

class CheckISEVMExistsCommand(Command):
    """Command to check if the ISE VM exists."""
    
    def __init__(self):
        super().__init__("Check ISE VM exists")
    
    def execute(self, context: Context):
        all_vms = context.get("all_vms")
        if not all_vms:
            # If not already loaded, get the VM list
            list_cmd = ListVMsCommand(running_only=False)
            all_vms = list_cmd.execute(context)
        
        if ISE_VM_NAME in all_vms:
            log(f"ISE VM '{ISE_VM_NAME}' found", "green")
            context.set("ise_vm_exists", True)
            return True
        else:
            error_msg = f"ISE VM '{ISE_VM_NAME}' not found in VirtualBox"
            raise RuntimeError(error_msg)

class StartISEVMCommand(Command):
    """Command to start the ISE VM."""
    
    def __init__(self):
        super().__init__("Start ISE VM")
    
    def execute(self, context: Context):
        # Check if VM is already running
        running_vms = context.get("running_vms", [])
        if ISE_VM_NAME in running_vms:
            log(f"ISE VM '{ISE_VM_NAME}' is already running", "yellow")
            context.set("ise_vm_running", True)
            return True
        
        # Start the VM in headless mode
        log(f"Starting ISE VM '{ISE_VM_NAME}' in headless mode...", "cyan")
        subprocess.run([VBOXMANAGE_EXE, "startvm", ISE_VM_NAME, "--type", "headless"], 
                       capture_output=True, text=True, check=True)
        
        log(f"ISE VM '{ISE_VM_NAME}' started successfully", "green")
        
        # Wait a moment for VM to initialize
        log("Waiting for VM to initialize...", "cyan")
        time.sleep(5)
        
        # Verify it's running by checking again
        result = subprocess.run([VBOXMANAGE_EXE, "list", "runningvms"], 
                               capture_output=True, text=True, check=True)
        
        if result.stdout.strip():
            running_vms = []
            for line in result.stdout.strip().split('\n'):
                vm_name = line.split('"')[1] if '"' in line else line.split()[0]
                running_vms.append(vm_name)
            context.set("running_vms", running_vms)
            
            if ISE_VM_NAME in running_vms:
                context.set("ise_vm_running", True)
                return True
        
        error_msg = f"ISE VM '{ISE_VM_NAME}' failed to start properly"
        raise RuntimeError(error_msg)

class GetVMIPCommand(Command):
    """Command to get the IP address of the ISE VM."""
    
    def __init__(self):
        super().__init__("Get ISE VM IP address")
    
    def execute(self, context: Context):
        if not context.get("ise_vm_running"):
            raise RuntimeError(f"ISE VM '{ISE_VM_NAME}' is not running")
        
        result = subprocess.run([VBOXMANAGE_EXE, "guestproperty", "enumerate", ISE_VM_NAME], 
                                capture_output=True, text=True, check=True)
        
        property_lines = result.stdout.strip().split('\n')
        
        for line in property_lines:
            if '/VirtualBox/GuestInfo/Net/0/V4/IP' in line:
                ip_start = line.find("'") + 1
                ip_end = line.find("'", ip_start)
                if ip_start > 0 and ip_end > ip_start:
                    vm_ip = line[ip_start:ip_end]
                    log(f"ISE VM IP address: {vm_ip}", "green")
                    context.set("ise_vm_ip", vm_ip)
                    return vm_ip
        
        error_msg = "Could not find IP address for ISE VM"
        raise RuntimeError(error_msg)

class WaitForSSHCommand(Command):
    """Command to wait for SSH service to become available."""
    
    def __init__(self, timeout=180):
        super().__init__("Wait for SSH service")
        self.timeout = timeout
    
    def execute(self, context: Context):
        vm_ip = context.get("ise_vm_ip")
        if not vm_ip:
            raise RuntimeError("VM IP not available")
        
        import socket
        
        check_interval = 5
        elapsed_time = 0
        
        log(f"Waiting for SSH service on {vm_ip}:22 (timeout: {self.timeout}s)...", "cyan")
        
        while elapsed_time < self.timeout:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((vm_ip, 22))
                sock.close()
                
                if result == 0:
                    log(f"SSH service is available on {vm_ip}:22", "green")
                    context.set("ssh_available", True)
                    return True
                
            except Exception as e:
                log(f"Connection attempt failed: {e}", "yellow")
            
            log(f"SSH not ready yet, waiting... ({elapsed_time}s/{self.timeout}s)", "yellow")
            time.sleep(check_interval)
            elapsed_time += check_interval
        
        error_msg = f"SSH service did not become available within {self.timeout} seconds"
        raise TimeoutError(error_msg)

class UpdateSSHConfigCommand(Command):
    """Command to update SSH configuration."""
    
    def __init__(self):
        super().__init__("Update SSH config")
    
    def execute(self, context: Context):
        vm_ip = context.get("ise_vm_ip")
        if not vm_ip:
            raise RuntimeError("Could not retrieve ISE VM IP address")
        
        ssh_config_path = os.path.expanduser("~/.ssh/config")
        
        # Create ~/.ssh directory if it doesn't exist
        ssh_dir = os.path.dirname(ssh_config_path)
        os.makedirs(ssh_dir, exist_ok=True)
        
        # Read existing config
        existing_lines = self._read_ssh_config(ssh_config_path)
        
        # Remove existing ise-vm config and add new one
        filtered_lines = self._remove_existing_ise_config(existing_lines)
        ise_config = self._create_ise_config_block(vm_ip)
        
        # Add the new config block
        if filtered_lines and not filtered_lines[-1].strip() == "":
            filtered_lines.append("")
        filtered_lines.extend(ise_config)
        
        # Write updated config
        self._write_ssh_config(ssh_config_path, filtered_lines)
        
        log(f"Updated SSH config at {ssh_config_path} with IP {vm_ip}", "green")
        context.set("ssh_config_updated", True)
    
    def _read_ssh_config(self, ssh_config_path):
        """Read existing SSH config file and return lines."""
        existing_lines = []
        if os.path.exists(ssh_config_path):
            with open(ssh_config_path, 'r') as f:
                existing_lines = f.read().splitlines()
        return existing_lines
    
    def _write_ssh_config(self, ssh_config_path, lines):
        """Write lines to SSH config file."""
        with open(ssh_config_path, 'w') as f:
            f.write('\n'.join(lines) + '\n')
    
    def _remove_existing_ise_config(self, lines):
        """Remove existing ise-vm host block from SSH config lines."""
        filtered_lines = []
        in_ise_block = False
        
        for line in lines:
            if line.strip().startswith("Host ise-vm"):
                in_ise_block = True
                continue
            elif line.strip().startswith("Host ") and in_ise_block:
                in_ise_block = False
                filtered_lines.append(line)
            elif not in_ise_block:
                filtered_lines.append(line)
        
        return filtered_lines
    
    def _create_ise_config_block(self, vm_ip):
        """Create SSH config block for ISE VM with given IP."""
        return [
            f"Host {ISE_VM_HOSTNAME}",
            f"    HostName {vm_ip}",
            f"    User {ISE_VM_USER}", 
            "    HostKeyAlgorithms +ssh-rsa",
            "    PubkeyAcceptedAlgorithms +ssh-rsa"
        ]

class SetupSSHKeysCommand(Command):
    """Command to setup SSH keys on the ISE VM."""
    
    def __init__(self):
        super().__init__("Setup SSH keys")
    
    def execute(self, context: Context):
        vm_ip = context.get("ise_vm_ip")
        if not vm_ip:
            raise RuntimeError("VM IP not available")
        
        # Read local public key
        pub_key_path = os.path.expanduser("~/.ssh/id_rsa.pub")
        if not os.path.exists(pub_key_path):
            raise FileNotFoundError("SSH public key not found. Run ssh-keygen first.")
        
        with open(pub_key_path, 'r') as f:
            pub_key = f.read().strip()
        
        # Connect and setup authorized_keys
        client = self._ssh_connect_with_password(vm_ip, ISE_VM_USER, ISE_VM_PASSWORD)
        
        commands = [
            "mkdir -p ~/.ssh",
            "chmod 700 ~/.ssh",
            f"echo '{pub_key}' >> ~/.ssh/authorized_keys",
            "chmod 600 ~/.ssh/authorized_keys",
            "sudo sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config",
            "sudo sed -i 's/^#*AuthorizedKeysFile.*/AuthorizedKeysFile .ssh\\/authorized_keys/' /etc/ssh/sshd_config",
            "sudo sed -i 's/^#*RSAAuthentication.*/RSAAuthentication yes/' /etc/ssh/sshd_config",
        ]
        
        for cmd in commands:
            stdin, stdout, stderr = client.exec_command(cmd)
            if stderr.read():
                log(f"Warning executing '{cmd}': {stderr.read().decode()}", "yellow")
        
        client.close()
        log("SSH keys setup completed", "green")
        context.set("ssh_keys_setup", True)
    
    def _ssh_connect_with_password(self, hostname, username, password):
        """Connect to SSH with password and return client."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            client.connect(hostname, username=username, password=password, 
                          disabled_algorithms={'pubkeys': ['rsa-sha2-256', 'rsa-sha2-512']})
            return client
        except Exception as e:
            log(f"SSH connection failed: {e}", "red")
            raise

class VerifySSHConnectionCommand(Command):
    """Command to verify SSH connection using public key authentication."""
    
    def __init__(self):
        super().__init__("Verify SSH connection")
    
    def execute(self, context: Context):
        vm_ip = context.get("ise_vm_ip")
        if not vm_ip:
            raise RuntimeError("VM IP not available")
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect using SSH keys (no password)
            client.connect(vm_ip, username=ISE_VM_USER, 
                            disabled_algorithms={'pubkeys': ['rsa-sha2-256', 'rsa-sha2-512']})
            
            # Execute test command
            stdin, stdout, stderr = client.exec_command('lsb_release -a')
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            
            if error:
                log(f"Command error: {error}", "yellow")
            
            if output:
                log("SSH public key authentication successful!", "green")
                log(f"Target system info:\n{output}", "cyan")
            
            client.close()
            context.set("ssh_verified", True)
            return True
            
        except Exception as e:
            log(f"SSH public key authentication failed: {e}", "red")
            return False

def main():
    log_job_start("Configure ISE VM SSH access")
    
    try:
        context = Context()
        executor = CommandExecutor()
        
        # Define the command sequence
        commands = [
            CheckVBoxManageCommand(),
            ListVMsCommand(running_only=False),  # Load all VMs first
            CheckISEVMExistsCommand(),
            ListVMsCommand(running_only=True),   # Check running VMs
            StartISEVMCommand(),
            GetVMIPCommand(),
            WaitForSSHCommand(),
            UpdateSSHConfigCommand()
        ]
        
        # Execute main commands
        executor.execute_commands(commands, context)
        
        # Try to setup SSH keys (optional)
        try:
            ssh_commands = [
                SetupSSHKeysCommand(),
                VerifySSHConnectionCommand()
            ]
            executor.execute_commands(ssh_commands, context)
            log("SSH configuration complete. You can now connect with: ssh ise", "green")
        except Exception as e:
            log(f"SSH key setup failed: {e}", "red")
            log("You can manually setup keys using ssh-copy-id", "yellow")
        
        if context.get("ssh_verified"):
            log("You can now connect to the ISE VM using: ssh ise", "green")
            log_job_success("Configure ISE VM SSH access")
        else:
            log("SSH connection verification failed. Please check your setup.", "red")
            log_job_failed("Configure ISE VM SSH access", "SSH verification failed")
            
    except Exception as e:
        log_job_failed("Configure ISE VM SSH access", str(e))
        raise

if __name__ == "__main__":
    main()