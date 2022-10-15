import errno
import os
import shutil
import subprocess
import sys
from multiprocessing import Process

import psutil


# confirm yes or no with user before doing something
def ask(question):
    reply = str(input(question + ' (y/n): ')).lower().strip()
    if reply[0] == 'y':
        return True
    if reply[0] == 'n':
        return False
    else:
        return ask(question)


# replace line in file with a new line
def replace_line(file_path, to_replace, replace_with):
    with open(file_path, 'r') as f:
        lines = f.readlines()
    with open(file_path, 'w') as f:
        for line in lines:
            f.write(line.replace(to_replace, replace_with))


def firewall_config():
    allow = ["http", "https"]
    deny = ["23", "2049", "515", "111", "1080", "4444", "6660:6669/tcp", "6660:6669/udp", "161", "31337"]

    output = subprocess.check_output("ufw enable", shell=True, text=True)
    output += subprocess.check_output("yes | ufw reset", shell=True, text=True)
    output += subprocess.check_output("ufw enable", shell=True, text=True)
    for i in allow:
        output += subprocess.check_output("ufw allow " + i, shell=True, text=True)
    for i in deny:
        output += subprocess.check_output("ufw deny " + i, shell=True, text=True)
    output += subprocess.check_output("ufw logging high", shell=True, text=True)

    with open('logs/firewall.log', 'w') as firelog:
        firelog.write(output)


def dns_flush():
    commands = ["/etc/init.d/dnsmasq restart", "/etc/init.d/ncsd -i hosts", "/etc/init.d/ncsd reload", "rndc flush",
                "free", "sync", "echo 3 > /proc/sys/vm/drop_caches", "free", "service xinetd reload"]
    dnsOutput = ""

    for command in commands:
        try:
            dnsOutput += subprocess.check_output(command, shell=True, text=True)
            dnsOutput += "\n"
        except Exception as e:
            dnsOutput += "\n---ERROR" + command + "---ERROR\n" + str(e) + "\n"

    with open('logs/dnsflush.log', 'w') as dnslog:
        dnslog.write(dnsOutput)


def scans():
    commands = ["chkrootkit", "rkhunter -ppropupd", "rkhunter -c --enable all --disable none", "lynis update info",
                "lynis audit system", "freshclam", "clamscan -r -i"]
    scanOutput = ""
    for command in commands:
        try:
            scanOutput += "\n------" + command + "------\n"
            scanOutput += subprocess.check_output(command, shell=True, text=True)
        except Exception as e:
            scanOutput += "\n---ERROR" + command + "---ERROR\n" + str(e) + "\n"

    with open('logs/scans.log', 'w') as scanlog:
        scanlog.write(scanOutput)


if not ask("Forensics answered? Updates and sources configured?"):
    sys.exit()

if not (os.path.isfile("users.txt") and os.path.isfile("admins.txt")):
    print("users.txt and admins.txt not found")
    sys.exit()

if os.geteuid() != 0:
    sys.exit("This script must be run as root")

# create directories and copy log files to log directory
if not os.path.exists("logs"):
    os.mkdir("logs")
if not os.path.exists("backups"):
    os.mkdir("backups")
logs = ["/var/log/auth.log", "/var/log/dkpg.log", "/var/log/messages", "/var/log/secure", "/var/log/apt/history.log",
        "/root/bash_history"]
for log in logs:
    if os.path.isfile(log):
        shutil.copy(log, "logs")
    else:
        print(log.rsplit("/", -1)[-1] + " not found")

# install updates and packages
subprocess.call('apt-get update', shell=True)
subprocess.call('apt-get upgrade -y', shell=True)
subprocess.call('apt-get install ufw rkhunter tree debsums libpam-pwquality chkrootkit clamav lynis -y', shell=True)
subprocess.call('apt-get autoremove -y', shell=True)
subprocess.call('apt-get autoclean -y', shell=True)
subprocess.call('apt-get check', shell=True)

# firewall stuff in background
print("Configuring firewall...")
firewall = Process(target=firewall_config)
firewall.start()

# flushing dns caches in background
print("Flushing dns...")
dns = Process(target=dns_flush())
dns.start()

# scans in background
print("Running scans...")
scans = Process(target=scans)
scans.start()

# lightdm stuff
if os.path.isfile("/etc/lightdm/lightdm.conf"):
    with open("/etc/lightdm/lightdm.conf", "a") as file:
        file.write("autologin-guest=false")
        file.write("allow-guest=false")
        file.write("greeter-hide-users=true")

# lock root account
# subprocess.call("passwd -l root", shell=True)

print("Changing password policies")
# password policies
replace_line("/etc/login.defs", "PASS_MAX_DAYS\t99999", "PASS_MAX_DAYS\t365")
replace_line("/etc/login.defs", "PASS_MIN_DAYS\t0", "PASS_MIN_DAYS\t1")
# common-password
replace_line("/etc/pam.d/common-password", "password\trequisite\t\t\tpam_pwquality.so retry=3",
             "password\trequisite\t\t\tpam_pwquality.so retry=3 minlen=10 difok=4 ucredit=-1 lcredit=-1 ocredit=-1 dcredit=-1 reject_username enforce_for_root")
replace_line("/etc/pam.d/common-password",
             "password\t[success=1 default=ignore]\tpam_unix.so obscure use_authtok try_first_pass sha512",
             "password\t[success=1 default=ignore]\tpam_unix.so obscure use_authtok try_first_pass sha512 minlen=10 remember=5")
# common-auth
replace_line("/etc/pam.d/common-auth", "auth\t[success=1 default=ignore]\tpam_unix.so nullok_secure",
             "auth\trequired\t\t\tpam_tally2.so deny=4 unlock_time=60\nauth\t[success=1 default=ignore]\tpam_unix.so nullok_secure")

# common-account
replace_line("/etc/pam.d/common-account", "account\t[success=1 new_authtok_reqd=done default=ignore]\tpam_unix.so",
             "account\t[success=1 new_authtok_reqd=done default=ignore]\tpam_unix.so\naccount\trequired\t\t\tpam_tally2.so")

# open passwd file and if users are not in users.txt or admins.txt, delete them

with open('logs/user_changes.log', 'w') as user_changes:
    with open("/etc/passwd") as passwd:
        lines = passwd.readlines()
        for line_number, line in enumerate(lines):
            split = line.split(":")[0]
            user = split[0]
            uid = int(split[2])
            gid = int(split[3])
            if uid >= 1000:
                if user not in open("users.txt").read() and user not in open("admins.txt").read():
                    if ask("User not in lists. Delete " + user + "?"):
                        subprocess.call("userdel -r " + user, shell=True)
                        print(user + " deleted")
                        user_changes.write(user + " deleted")
                    else:
                        print(user + " not deleted")
                # remove user from sudo or adm group if they are in sudo or adm group in /etc/group
                with open("/etc/group", "r") as groups:
                    if user in open("users.txt").read():
                        for group in groups:
                            if group.startswith("adm") and user in group:
                                subprocess.call("gpasswd -d " + user + " adm", shell=True)
                                print(user + " removed from adm group")
                                user_changes.write(user + " removed from adm group")
                            if group.startswith("sudo") and user in group:
                                subprocess.call("gpasswd -d " + user + " sudo", shell=True)
                                print(user + " removed from sudo group")
                                user_changes.write(user + " removed from sudo group")
                    if user in open("admins.txt").read():
                        for group in groups:
                            if group.startswith("adm") and user not in group:
                                subprocess.call("gpasswd -a " + user + " adm", shell=True)
                                print(user + " added to adm group")
                                user_changes.write(user + " added to adm group")
                            if group.startswith("sudo") and user not in group:
                                subprocess.call("gpasswd -a " + user + " sudo", shell=True)
                                print(user + " added to sudo group")
                                user_changes.write(user + " added to sudo group")
            if user is not "root" and (uid == 0 or gid == 0):
                lines[line_number] = "#" + line
                print("commented out " + user + " because uid 0 and not root")
                user_changes.write(user + " commented out because uid 0 and not root")
                with open("/etc/passwd", "w") as passwdw:
                    passwdw.writelines(lines)

# prevent network root logon
subprocess.call("echo > /etc/securetty", shell=True)

# change ownership of files
subprocess.call("chown root:root /etc/securetty", shell=True)
subprocess.call("chmod 0600 /etc/securetty", shell=True)
subprocess.call("chmod 644 /etc/crontab", shell=True)
subprocess.call("chmod 640 /etc/ftpusers", shell=True)
subprocess.call("chmod 440 /etc/inetd.conf", shell=True)
subprocess.call("chmod 440 /etc/xinetd.conf", shell=True)
subprocess.call(" 400 /etc/inetd.d", shell=True)
subprocess.call("chmod 644 /etc/hosts.allow", shell=True)
subprocess.call("chmod 440 /etc/sudoers", shell=True)
subprocess.call("chmod 640 /etc/shadow", shell=True)
subprocess.call("chown root:root /etc/shadow", shell=True)
subprocess.call("chmod 644 /etc/passwd", shell=True)
subprocess.call("chmod 644 /etc/group", shell=True)

# Remove unwanted aliases
subprocess.call("unalias -a", shell=True)
subprocess.call("alias egrep='egrep --color=auto'", shell=True)
subprocess.call("alias fgrep='fgrep --color=auto'", shell=True)
subprocess.call("alias grep='grep --color=auto'", shell=True)
subprocess.call("alias l='ls -CF'", shell=True)
subprocess.call("alias la='ls -A'", shell=True)
subprocess.call("alias ll='ls -alF'", shell=True)
subprocess.call("alias ls='ls --color=auto'", shell=True)

# prevent anything from running if control_alt_delete is present
if os.isfile("/etc/init/control-alt-delete.conf"):
    with open("/etc/init/control-alt-delete.conf", "w") as control_alt_delete:
        control_alt_delete.write("start on control-alt-delete\ntask\nexec false")

# clean copies of sudoers stuff
shutil.copy("cleanfiles/sudoers", "/etc/sudoers")
shutil.copy("cleanfiles/README", "/etc/sudoers.d/README")

# removes any sudo configurations
for file in os.listdir("/etc/sudoers.d"):
    if file != "README":
        subprocess.call("mv /etc/sudoers.d/" + file + " backups/bad_sudo_configs/" + file, shell=True)

# enable tcp syn cookies
with open("/etc/sysctl.d/10-network-security.conf", "a") as sysctl:
    sysctl.write("net.ipv4.tcp_syncookies = 1")
    sysctl.write("net.ipv4.ip_forward = 0")
    sysctl.write("net.ipv4.conf.all.send_redirects = 0")
    sysctl.write("net.ipv4.conf.default.send_redirects = 0")
    sysctl.write("net.ipv4.conf.all.accept_redirects = 0")
    sysctl.write("net.ipv4.conf.default.accept_redirects = 0")
    sysctl.write("net.ipv4.conf.all.secure_redirects = 0")
    sysctl.write("net.ipv4.conf.default.secure_redirects = 0")
subprocess.call("sysctl --system", shell=True)

# clearing hosts file
subprocess.call("cp /etc/hosts backups/hosts", shell=True)
with open("/etc/hosts", "w") as hosts:
    hosts.write("127.0.0.1	localhost\n"
                "127.0.1.1	ubuntu\n"
                "::1     ip6-localhost ip6-loopback\n"
                "fe00::0 ip6-localnet\n"
                "ff00::0 ip6-mcastprefix\n"
                "ff02::1 ip6-allnodes\n"
                "ff02::2 ip6-allrouters\n")

# harden sshd server
if os.ispath("/etc/sshd/ssh_config"):
    with open("/etc/ssh/sshd_config", "a") as sshd_config:
        sshd_config.write("PasswordAuthentication no")
        sshd_config.write("PermitRootLogin no")
        sshd_config.write("PermitEmptyPasswords no")
        sshd_config.write("Protocol 2")
        sshd_config.write("ClientAliveInterval 180")
        sshd_config.write("MaxAuthTries 3")
        sshd_config.write("X11Forwarding no")
        sshd_config.write("IgnoreRhosts yes")
        sshd_config.write("UseDNS yes")
        sshd_config.write("PubkeyAuthentication yes")

# harden apache
if os.ispath("/etc/apache2/apache2.conf"):
    subprocess.call("chown -R root:root /etc/apache", shell=True)
    subprocess.call("chown -R root:root /etc/apache2", shell=True)
    with open("/etc/apache2/apache2.conf", "a") as apache2_config:
        apache2_config.write("<Directory />")
        apache2_config.write("    AllowOverride None")
        apache2_config.write("    Order deny,allow")
        apache2_config.write("    Deny from all")
        apache2_config.write("</Directory>")
        apache2_config.write("UserDir disabled root")

# remove netcat backdoors
for proc in psutil.process_iter(['name', 'pid', 'exe']):
    if proc.name() == "nc" or proc.name() == "netcat" or proc.name() == "ncat":
        name = proc.info['name']
        pid = str(proc.info['pid'])
        exe = proc.info['exe']
        with open('logs/netcat_backdoors.log', 'a') as netcat_backdoors:
            netcat_backdoors.write(name + " moved from " + exe + " to backups/" + exe.rsplit('/')[-1])
            subprocess.call(str("cp " + exe + " backups/" + exe.rsplit('/')[-1]), shell=True)
            subprocess.call("rm " + exe, shell=True)
            subprocess.call("kill -9 " + pid, shell=True)

# remove any bad crontab files
for file in os.listdir("/etc/cron.d"):
    if file != "README":
        subprocess.call("mv /etc/cron.d/" + file + " backups/bad_crontab_files/" + file, shell=True)

# /etc/rc.local should be empty
with open("/etc/rc.local", "w") as rc_local:
    rc_local.write("#!/bin/sh -e\nexit 0")

# secure shared memory
with open("/etc/fstab", "a+") as fstab:
    if "#already run" not in fstab.read():
        fstab.write("#already run\nnone     /run/shm     tmpfs     rw,noexec,nosuid,nodev     0     0")

# only allow root to use cron
subprocess.call("rm -f /etc/cron.deny", shell=True)
subprocess.call("rm -f /etc/at.deny", shell=True)
subprocess.call("touch /etc/cron.allow", shell=True)
subprocess.call("touch /etc/at.allow", shell=True)
with open("/etc/cron.allow", "w") as cron_allow:
    cron_allow.write("root")
with open("/etc/at.allow", "w") as at_allow:
    at_allow.write("root")
subprocess.call("chmod 400 /etc/cron.allow", shell=True)
subprocess.call("chmod 400 /etc/at.allow", shell=True)

# remove bad programs
packages = {"john": "john john-data", "telnetd": "openbsd-inetd telnetd", "logkeys": "logkeys",
            "hydra": "hydra-gtk hydra", "fakeroot": "fakeroot",
            "nmap": "nmap zenmap", "crack": "crack crack-common", "medusa": "libssh2-1 medusa", "nikto": "nikto",
            "tightvnc": "xtightvncviewer", "bind9": "bind9 bind9utils",
            "avahi": "avahi-autoipd avahi-daemon avahi-utils",
            "cupsd": "cups cups-core-drivers printer-driver-hpcups cupsddk indicator-printers printer-driver-splix hplip printer-driver-gutenprint bluez-cups printer-driver-postscript-hp cups-server-common cups-browsed cups-bsd cups-client cups-common cups-daemon cups-ppdc cups-filters cups-filters-core-drivers printer-driver-pxljr printer-driver-foo2zjs foomatic-filters cups-pk-helper",
            "postfix": "postfix", "nginx": "nginx nginx-core nginx-common", "frostwire": "frostwire",
            "vuze": "azureus vuze",
            "samba": "samba samba-common samba-common-bin", "apache2": "apache2 apache2.2-bin", "ftp": "ftp",
            "vsftpd": "vsftpd", "netcat": "netcat-traditional netcat-openbsd",
            "openssh": "openssh-server openssh-client ssh",
            "weplab": "weplab", "pyrit": "pyrit", "mysql": "mysql-server php5-mysql", "php5": "php5",
            "proftpd-basic": "proftpd-basic", "filezilla": "filezilla",
            "postgresql": "postgresql", "irssi": "irssi",
            "wireshark": "wireshark wireshark-common wireshark-qt wireshark-gtk libwireshark-data libwireshark13",
            "libpcap": "libpcap-dev libpcap0.8 libpcap0.8-dev libpcap0.9 libpcap0.9-dev",
            "metasploit": "metasploit-framework",
            "dirb": "dirb", "aircrack-ng": "aircrack-ng",
            "sqpmap": "sqpmap", "wifite": "wifite wifite-gui wifite-cli",
            "autopsy": "autopsy autopsy-gui autopsy-cli",
            "setoolkit": "setoolkit", "ncrack": "ncrack", "nmap-ncat": "nmap-ncat",
            "skipfish": "skipfish", "maltego": "maltego", "maltegoce": "maltegoce",
            "nessus": "nessus nessus-cli nessus-server",
            "beef": "beef beef-xss beef-xss-ruby beef-xss-python",
            "apktool": "apktool", "snort": "snort", "suricata": "suricata",
            "yersinia": "yersinia", "freeciv": "freeciv", "oph-crack": "oph-crack", "kismet": "kismet",
            "minetest": "minetest"}

subprocess.call("dpkg-query -f '${binary:Package}\n' -W > packages_list.txt", shell=True)
with open("packages_list.txt", "r") as packages_list:
    for package_name in packages_list:
        if package_name in packages:
            if ask("Remove " + package_name + "?"):
                subprocess.call("dpkg --purge " + packages[package_name], shell=True)
                print("Removed " + package_name)

with open('logs/sus_files.log', 'w') as suspicious_files:
    output = subprocess.check_output("timeout 60 find / -nouser -o -nogroup", shell=True, text=True)
    output += subprocess.check_output("timeout 60 find / -perm -2 ! -type l -ls", shell=True, text=True)
    suspicious_files.write(output)

print("Waiting for background processes to finish...")
firewall.join()
dns.join()
scans.join()

print("Script finished. Check dpkg for other bad packages. Check for bad media files.")
