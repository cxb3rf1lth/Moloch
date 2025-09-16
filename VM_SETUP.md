# RexPloit Testing Environment Setup

This guide provides instructions for setting up dedicated testing environments for RexPloit, either through Vagrant or Docker.

## Option 1: Vagrant VM (Recommended for Testing)

### Prerequisites
- [VirtualBox](https://www.virtualbox.org/wiki/Downloads)
- [Vagrant](https://www.vagrantup.com/downloads)

### Setup Steps

1. **Start the VM**:
   ```bash
   cd /path/to/rexploit
   vagrant up
   ```
   This will download the Kali Linux box and provision it with all necessary dependencies.

2. **SSH into the VM**:
   ```bash
   vagrant ssh
   ```
   You'll see the RexPloit welcome banner with usage instructions.

3. **Run RexPloit**:
   ```bash
   # Within the VM
   rexploit
   ```
   
   For CLI mode:
   ```bash
   rexploit-cli
   ```

4. **Shutdown or Pause the VM**:
   ```bash
   # From host machine
   vagrant suspend  # To pause
   vagrant halt     # To shutdown
   ```

5. **Remove the VM**:
   ```bash
   # From host machine
   vagrant destroy
   ```

### VM Network Details
- Private network with DHCP
- Forwarded ports:
  - 4444 (RexPloit default listener)
  - 8080 (Web interface)
  - 8888 (C2 framework)

### Pre-installed Tools
- RexPloit (latest from GitHub)
- Nmap
- Metasploit Framework
- Wireshark
- Burp Suite
- Git and other essentials

## Option 2: Docker Container

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)

### Setup Steps

1. **Start the Container**:
   ```bash
   cd /path/to/rexploit
   docker-compose up -d
   ```

2. **Access the Container**:
   ```bash
   docker exec -it rexploit-container bash
   ```

3. **Run RexPloit**:
   ```bash
   # Within the container
   rexploit
   ```

4. **Stop the Container**:
   ```bash
   # From host machine
   docker-compose down
   ```

### Container Network Details
- Exposed ports:
  - 4444 (RexPloit default listener)
  - 8080 (Web interface)
  - 8888 (C2 framework)

## Additional Setup Options

### Cloud-Based VM

For a cloud-based testing environment, you can:

1. **Create a cloud VM** on providers like AWS, Azure, or Digital Ocean
2. Use the following command to automatically set up the environment:

```bash
curl -sSL https://raw.githubusercontent.com/cxb3rf1lth/Moloch/main/vm_setup.sh | sudo bash
```

### Manual VM Setup

If you prefer to set up your own VM:

1. Create a new VM with Kali Linux or Ubuntu
2. Install dependencies:
   ```bash
   sudo apt update && sudo apt install -y git python3 python3-pip
   ```
3. Clone and set up RexPloit:
   ```bash
   git clone https://github.com/cxb3rf1lth/Moloch.git rexploit
   cd rexploit
   pip3 install -r requirements.txt
   ```
4. Run RexPloit:
   ```bash
   python3 rexploit.py
   ```

## Security Considerations

1. **Isolation**: Always run RexPloit in an isolated environment
2. **Authorization**: Ensure you have proper authorization for all targets
3. **Network Separation**: Use a separate network for testing
4. **Legal Compliance**: Adhere to all applicable laws and regulations

## Troubleshooting

### VM Not Starting
- Ensure VirtualBox and Vagrant are up to date
- Check for sufficient system resources
- Try with `vagrant up --debug` for verbose output

### Docker Container Issues
- Ensure Docker service is running
- Try rebuilding with `docker-compose build --no-cache`
- Check port conflicts with `netstat -tuln`

### RexPloit Execution Problems
- Verify Python version (3.8+ required)
- Check all dependencies with `python3 rexploit.py --check`
- Review logs in `logs/` directory