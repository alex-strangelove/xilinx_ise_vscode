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
PROJECTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "projects")
SHARED_FOLDER_NAME = "projects" 
VM_MOUNT_POINT = "/home/ise/projects"

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

class ShutdownISEVMCommand(Command):
    """Command to shutdown the ISE VM."""
    
    def __init__(self):
        super().__init__("Shutdown ISE VM")
    
    def execute(self, context: Context):
        # Check if VM is running
        running_vms = context.get("running_vms", [])
        if ISE_VM_NAME not in running_vms:
            log(f"ISE VM '{ISE_VM_NAME}' is not running", "yellow")
            context.set("ise_vm_running", False)
            return True
        
        log("Graceful shutdown timed out, forcing power off...", "yellow")
        subprocess.run([VBOXMANAGE_EXE, "controlvm", ISE_VM_NAME, "poweroff"], 
                      capture_output=True, text=True, check=True)
        
        # Wait for VM to shutdown
        log("Waiting for VM to shutdown...", "cyan")
        timeout = 60
        elapsed = 0
        check_interval = 3
        
        while elapsed < timeout:
            # Check if VM is still running
            result = subprocess.run([VBOXMANAGE_EXE, "list", "runningvms"], 
                                   capture_output=True, text=True, check=True)
            
            if not result.stdout.strip() or ISE_VM_NAME not in result.stdout:
                log(f"ISE VM '{ISE_VM_NAME}' shutdown successfully", "green")
                context.set("ise_vm_running", False)
                return True
            
            time.sleep(check_interval)
            elapsed += check_interval
            log(f"VM still running, waiting... ({elapsed}s/{timeout}s)", "yellow")
        
        # Give VirtualBox a moment to process the poweroff
        time.sleep(5)
        
        context.set("ise_vm_running", False)
        log(f"ISE VM '{ISE_VM_NAME}' powered off", "green")
        return True

class SetupSharedFolderCommand(Command):
    """Command to setup VirtualBox shared folder for projects."""
    
    def __init__(self):
        super().__init__("Setup shared folder")
    
    def execute(self, context: Context):
        # Create projects directory if it doesn't exist
        if not os.path.exists(PROJECTS_DIR):
            try:
                log(f"Projects directory not found, creating: {PROJECTS_DIR}", "yellow")
                os.makedirs(PROJECTS_DIR, exist_ok=True)
            except Exception as e:
                raise RuntimeError(f"Failed to create projects directory: {e}")
        
        # Ensure VM is shutdown for shared folder modifications
        running_vms = context.get("running_vms", [])
        if ISE_VM_NAME in running_vms:
            raise RuntimeError("VM must be shutdown to modify shared folders")
        
        # Remove existing shared folder if it exists
        try:
            log(f"Removing existing shared folder '{SHARED_FOLDER_NAME}' if it exists...", "cyan")
            subprocess.run([VBOXMANAGE_EXE, "sharedfolder", "remove", ISE_VM_NAME, 
                           "--name", SHARED_FOLDER_NAME], 
                          capture_output=True, text=True, check=False)
        except Exception:
            # Ignore errors - folder might not exist
            pass
        
        # Add new shared folder
        log(f"Adding shared folder: {PROJECTS_DIR}", "cyan")
        subprocess.run([VBOXMANAGE_EXE, "sharedfolder", "add", ISE_VM_NAME,
                       "--name", SHARED_FOLDER_NAME, "--hostpath", PROJECTS_DIR,
                       "--automount"], 
                      capture_output=True, text=True, check=True)
        
        log(f"Shared folder '{SHARED_FOLDER_NAME}' created: {PROJECTS_DIR} -> {VM_MOUNT_POINT}", "green")
        context.set("shared_folder_setup", True)
        return True

class MountSharedFolderCommand(Command):
    """Command to mount shared folder inside the ISE VM."""
    
    def __init__(self):
        super().__init__("Mount shared folder in VM")
    
    def execute(self, context: Context):
        vm_ip = context.get("ise_vm_ip")
        if not vm_ip:
            raise RuntimeError("VM IP not available")
        
        # Connect to VM
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # Try with SSH keys first if configured
            if context.get("ssh_verified"):
                client.connect(vm_ip, username=ISE_VM_USER,
                              disabled_algorithms={'pubkeys': ['rsa-sha2-256', 'rsa-sha2-512']})
            else:
                # Fall back to password authentication
                client.connect(vm_ip, username=ISE_VM_USER, password=ISE_VM_PASSWORD,
                              disabled_algorithms={'pubkeys': ['rsa-sha2-256', 'rsa-sha2-512']})
        except Exception as e:
            log(f"SSH connection failed: {e}", "red")
            raise
        
        # Create mount point and add user to vboxsf group for permissions
        commands = [
            f"echo '{ISE_VM_PASSWORD}' | sudo -S mkdir -p {VM_MOUNT_POINT}",
            f"echo '{ISE_VM_PASSWORD}' | sudo -S chown {ISE_VM_USER}:{ISE_VM_USER} {VM_MOUNT_POINT}",
            f"echo '{ISE_VM_PASSWORD}' | sudo -S usermod -a -G vboxsf {ISE_VM_USER}"
        ]
        
        for cmd in commands:
            stdin, stdout, stderr = client.exec_command(cmd, get_pty=True)
            error = stderr.read().decode().strip()
            if error and "already a member" not in error and "Password:" not in error:
                log(f"Warning executing command: {error}", "yellow")
        
        # Mount the shared folder
        unmount_cmd = f"echo '{ISE_VM_PASSWORD}' | sudo -S umount {VM_MOUNT_POINT} 2>/dev/null || true"
        client.exec_command(unmount_cmd, get_pty=True)
        
        mount_cmd = f"echo '{ISE_VM_PASSWORD}' | sudo -S mount -t vboxsf -o uid={ISE_VM_USER},gid={ISE_VM_USER} {SHARED_FOLDER_NAME} {VM_MOUNT_POINT}"
        stdin, stdout, stderr = client.exec_command(mount_cmd, get_pty=True)
        error = stderr.read().decode().strip()
        if error and "already mounted" not in error and "Password:" not in error:
            client.close()
            raise RuntimeError(f"Failed to mount shared folder: {error}")
        
        # Verify the mount worked by listing contents
        stdin, stdout, stderr = client.exec_command(f"ls -la {VM_MOUNT_POINT}")
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        
        if error:
            client.close()
            raise RuntimeError(f"Failed to verify mount: {error}")
        
        log(f"Mount verification successful:", "green")
        log(f"Contents of {VM_MOUNT_POINT}:", "cyan")
        for line in output.split('\n')[:5]:  # Show first 5 lines
            log(f"  {line}", "yellow")
        
        client.close()
        log(f"Shared folder mounted at {VM_MOUNT_POINT}", "green")
        context.set("shared_folder_mounted", True)
        return True

class SetupPersistentMountCommand(Command):
    """Command to setup persistent mount in /etc/fstab."""
    
    def __init__(self):
        super().__init__("Setup persistent mount")
    
    def execute(self, context: Context):
        vm_ip = context.get("ise_vm_ip")
        if not vm_ip:
            raise RuntimeError("VM IP not available")
        
        # Connect to VM
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # Try with SSH keys first if configured
            if context.get("ssh_verified"):
                client.connect(vm_ip, username=ISE_VM_USER,
                              disabled_algorithms={'pubkeys': ['rsa-sha2-256', 'rsa-sha2-512']})
            else:
                # Fall back to password authentication
                client.connect(vm_ip, username=ISE_VM_USER, password=ISE_VM_PASSWORD,
                              disabled_algorithms={'pubkeys': ['rsa-sha2-256', 'rsa-sha2-512']})
        except Exception as e:
            log(f"SSH connection failed: {e}", "red")
            raise
        
        # Set up persistent mount in /etc/fstab
        fstab_entry = f"{SHARED_FOLDER_NAME} {VM_MOUNT_POINT} vboxsf uid={ISE_VM_USER},gid={ISE_VM_USER},auto 0 0"
        
        # Remove any existing entry
        remove_cmd = f"echo '{ISE_VM_PASSWORD}' | sudo -S sed -i '/{SHARED_FOLDER_NAME}/d' /etc/fstab"
        client.exec_command(remove_cmd, get_pty=True)
        
        # Add new entry
        add_cmd = f"echo '{fstab_entry}' | echo '{ISE_VM_PASSWORD}' | sudo -S tee -a /etc/fstab"
        stdin, stdout, stderr = client.exec_command(add_cmd, get_pty=True)
        error = stderr.read().decode().strip()
        if error and "Password:" not in error:
            log(f"Warning updating fstab: {error}", "yellow")
        
        client.close()
        log("Persistent mount configured in /etc/fstab", "green")
        context.set("persistent_mount_setup", True)
        return True

def main():
    log_job_start("Configure ISE VM SSH access and shared folders")
    
    try:
        context = Context()
        executor = CommandExecutor()
        
        # Initial setup - check VM and shutdown if running
        initial_commands = [
            CheckVBoxManageCommand(),
            ListVMsCommand(running_only=False),  # Check all VMs
            CheckISEVMExistsCommand(),
            ListVMsCommand(running_only=True),   # Check running VMs
            ShutdownISEVMCommand()               # Shutdown if running
        ]
        
        executor.execute_commands(initial_commands, context)
        
        # Setup shared folder while VM is off
        executor.execute_command(SetupSharedFolderCommand(), context)
        
        # Start VM and setup SSH access
        vm_setup_commands = [
            StartISEVMCommand(),
            GetVMIPCommand(),
            WaitForSSHCommand(),
            UpdateSSHConfigCommand()
        ]
        
        executor.execute_commands(vm_setup_commands, context)
        
        # Setup SSH keys and verify SSH connection
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
        
        # Mount shared folder and setup persistence
        try:
            mount_commands = [
                MountSharedFolderCommand(),
                SetupPersistentMountCommand()
            ]
            executor.execute_commands(mount_commands, context)
            log(f"Shared folder setup complete. Your projects are available at: {VM_MOUNT_POINT}", "green")
        except Exception as e:
            log(f"Shared folder mount failed: {e}", "red")
            log("You can manually mount the shared folder", "yellow")
        
        # Final status report
        if context.get("ssh_verified"):
            log("You can now connect to the ISE VM using: ssh ise", "green")
            if context.get("shared_folder_mounted"):
                log(f"Your projects are available at: {VM_MOUNT_POINT}", "green")
            log_job_success("Configure ISE VM SSH access and shared folders")
        else:
            log("Configuration completed with issues. Check the logs.", "yellow")
            log_job_failed("Configure ISE VM SSH access and shared folders", "SSH verification failed")
            
    except Exception as e:
        log_job_failed("Configure ISE VM SSH access and shared folders", str(e))
        raise

if __name__ == "__main__":
    main()