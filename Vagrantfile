# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  # Use Kali Linux as base image for penetration testing tools
  config.vm.box = "kalilinux/rolling"
  config.vm.hostname = "rexploit-vm"

  # Set up network
  config.vm.network "private_network", type: "dhcp"
  
  # Forward ports for RexPloit services
  config.vm.network "forwarded_port", guest: 4444, host: 4444  # Default RexPloit listener
  config.vm.network "forwarded_port", guest: 8080, host: 8080  # Web interface
  config.vm.network "forwarded_port", guest: 8888, host: 8888  # C2 framework

  # VM resources
  config.vm.provider "virtualbox" do |vb|
    vb.name = "RexPloit-TestingVM"
    vb.memory = 4096
    vb.cpus = 2
    vb.customize ["modifyvm", :id, "--clipboard", "bidirectional"]
    vb.customize ["modifyvm", :id, "--vram", "128"]
  end

  # Provision script to set up RexPloit
  config.vm.provision "shell", inline: <<-SHELL
    # Update system
    apt-get update
    apt-get upgrade -y

    # Install requirements
    apt-get install -y git python3 python3-pip python3-venv

    # Clone RexPloit repository
    cd /home/vagrant
    git clone https://github.com/cxb3rf1lth/Moloch.git rexploit
    chown -R vagrant:vagrant rexploit

    # Setup Python environment
    cd rexploit
    python3 -m venv .venv
    echo 'source /home/vagrant/rexploit/.venv/bin/activate' >> /home/vagrant/.bashrc
    /home/vagrant/rexploit/.venv/bin/pip install -r requirements.txt

    # Create convenient aliases
    echo 'alias rexploit="cd /home/vagrant/rexploit && python3 rexploit.py"' >> /home/vagrant/.bashrc
    echo 'alias rexploit-cli="cd /home/vagrant/rexploit && python3 rexploit.py --cli"' >> /home/vagrant/.bashrc

    # Install additional penetration testing tools
    apt-get install -y nmap metasploit-framework wireshark burpsuite

    # Clone C2 frameworks
    mkdir -p /home/vagrant/rexploit/c2_frameworks
    cd /home/vagrant/rexploit/c2_frameworks
    
    # Clone Villain
    git clone https://github.com/t3l3machus/Villain villain
    
    # Clone HoaxShell
    git clone https://github.com/t3l3machus/hoaxshell hoaxshell
    
    # Create sliver directory (user will need to download sliver binary separately)
    mkdir -p sliver
    
    # Set permissions
    chown -R vagrant:vagrant /home/vagrant/rexploit/c2_frameworks

    # Create welcome message
    cat > /etc/motd << 'EOF'
    
 ██████╗ ███████╗██╗  ██╗██████╗ ██╗      ██████╗ ██╗████████╗
 ██╔══██╗██╔════╝╚██╗██╔╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
 ██████╔╝█████╗   ╚███╔╝ ██████╔╝██║     ██║   ██║██║   ██║   
 ██╔══██╗██╔══╝   ██╔██╗ ██╔═══╝ ██║     ██║   ██║██║   ██║   
 ██║  ██║███████╗██╔╝ ██╗██║     ███████╗╚██████╔╝██║   ██║   
 ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   
 
 Professional Penetration Testing Framework - Testing VM
 FOR AUTHORIZED SECURITY TESTING ONLY
 
 Commands:
   rexploit       - Launch RexPloit with UI
   rexploit-cli   - Launch RexPloit in CLI mode
 
 Location:
   /home/vagrant/rexploit
 
EOF

    # Make it visible on login
    echo "cat /etc/motd" >> /home/vagrant/.bashrc

    echo "RexPloit VM setup completed successfully!"
  SHELL
end