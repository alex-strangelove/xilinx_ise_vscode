# Xilinx ISE 14.7 VSCode

## Requirements
 - Windows 10 or later
 - Oracle VirtualBox
 - Python >3.13.5
 
## Getting Started
 - [Install ISE 14.7 VM](https://docs.amd.com/r/en-US/ug1227-ise-vm-windows10/Installation) to `C:\Program Files\Oracle\VirtualBox`
 - Add `C:\Program Files\Oracle\VirtualBox` to your path

## Dependencies

```
python.exe -m pip install --upgrade pip
```

```
pip install -r requirements.txt
```

## Configuration

Run the configuration script to automatically set up SSH access to the ISE VM:

```bash
python configure.py
```

The `configure.py` script will:
- Check if VirtualBox and the ISE VM are properly installed
- Start the ISE VM in headless mode if not already running
- Obtain the VM's IP address
- Configure SSH access with public key authentication
- Update your SSH config file to enable easy connection with `ssh ise`

After successful configuration, you can connect to the ISE VM using:
```bash
ssh ise
```
