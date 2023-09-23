import os
import shutil
import subprocess
import sys
from configparser import ConfigParser
from multiprocessing import Process
from LoggerClass import Logger
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
    commands = ["chkrootkit", "rkhunter --propupd", "rkhunter -c --enable all --disable none", "lynis update info",
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


def userAudit(user_path, admin_path, logger: Logger):
    logger.logH1("USER AUDITING")
    # Initialize paths
    with open(user_path, 'r') as file:
        users = set(file.read().splitlines())
        users.add('nobody')
    with open(admin_path, 'r') as file:
        admins = set(file.read().splitlines())
    with open('/etc/passwd', 'r') as file:
        passwd_lines = file.readlines()

    # Filter out system users and collect information about users
    system_users = set()
    normal_users = set()
    for line in passwd_lines:
        if not line.startswith('#'):
            username = line.split(':')[0]
            if int(line.split(':')[2]) >= 1000:
                normal_users.add(username)
            else:
                system_users.add(username)

    # Remove unauthorized users
    unauthorized_users = normal_users - users - admins
    if (unauthorized_users):
        logger.logH2("Removing unauthorized users")
        with open('/etc/passwd', 'w') as file:
            for line in passwd_lines:
                username = line.split(':')[0]
                if username in unauthorized_users:
                    file.write('#' + line)
                    logger.logChange(f"Disabled unauthorized user: {username}")
                else:
                    file.write(line)
        logger.logHEnd()

    # Audit admin permissions
    logger.logH2("Checking user permissions...")
    for user in users:
        if user in admins:
            # Remove user from adm and sudo groups
            subprocess.run(['gpasswd', '-d', user, 'adm'])
            subprocess.run(['gpasswd', '-d', user, 'sudo'])
            logger.logChange(f"Removed admin privileges from {user}")

    for admin in admins:
        if admin not in users:
            # Add admin to adm and sudo groups
            subprocess.run(['gpasswd', '-a', admin, 'adm'])
            subprocess.run(['gpasswd', '-a', admin, 'sudo'])
            logger.logChange(f"Granted admin privileges to {admin}")
    logger.logHEnd()

    # Change to secure password
    logger.logH2("Changing passwords...")
    password = 'Cyb3rPatri0t!'
    for user in users.union(admins):
        subprocess.run(['echo', f'{user}:{password}', '|', 'chpasswd'])
        logger.logChange(f"Password changed for {user}")
    logger.logHEnd()

def test():
    logger = Logger('log.txt')
    userAudit('users.txt', 'admins.txt', logger)


def main():
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
    if not os.path.exists("backups/passconfig"):
        os.mkdir("backups/passconfig")
    if not os.path.exists("backups/sudoconfigs"):
        os.mkdir("backups/sudoconfigs")
    if not os.path.exists("backups/crontab"):
        os.mkdir("backups/crontab")
    if not os.path.exists("backups/sshd_config"):
        os.mkdir("backups/sshd_config")
    if not os.path.exists("backups/hosts"):
        os.mkdir("backups/hosts")

    logs = ["/var/log/auth.log", "/var/log/dkpg.log", "/var/log/messages", "/var/log/secure",
            "/var/log/apt/history.log",
            "/root/bash_history"]
    for log in logs:
        if os.path.isfile(log):
            shutil.copy(log, "logs")
        else:
            print(log.rsplit("/", -1)[-1] + " not found")

    # install updates and packages
    # apt update and upgrade called separately due to 20.04 crashing
    subprocess.call('apt-get install ufw rkhunter tree debsums libpam-pwquality chkrootkit clamav lynis -y', shell=True)
    subprocess.call('apt-get autoremove -y', shell=True)
    subprocess.call('apt-get autoclean -y', shell=True)
    subprocess.call('apt-get check', shell=True)

    # CIS benchmark
    # disable unused modules
    modules = ["cramfs", "squashfs", "udf", "usb-storage"]
    for module in modules:
        with open("/etc/modprobe.d/" + module + ".conf", "w") as f:
            f.write("install " + module + " /bin/true\n")
            f.write("blacklist " + module + "\n")

    # disable automount
    subprocess.call("apt purge autofs", shell=True)

    # randomize kernel va space
    with open("/etc/sysctl.d/60-kernel_sysctl.conf", "w") as f:
        f.write("kernel.randomize_va_space = 2\n")

    # disable core dumps
    with open("/etc/sysctl.conf", "a") as f:
        f.write("fs.suid_dumpable=0\n")

    # ensure auditd is installed
    subprocess.call("apt install auditd audispd-plugins", shell=True)
    subprocess.call("systemctl --now enable auditd", shell=True)

    # ensure apparmor and auditd are enabled in bootloader configuration
    with open("/etc/default/grub", "r+") as f:
        content = f.read()
        if "audit=1" not in content:
            f.seek(0)
            content = content.replace("GRUB_CMDLINE_LINUX=\"",
                                      "GRUB_CMDLINE_LINUX=\"audit=1 apparmor=1 security=apparmor "
                                      "audit_backlog_limit=8192")
            f.write(content)
            f.truncate()
    subprocess.call("update-grub", shell=True)

    # remove motd
    if os.path.isfile("/etc/motd"):
        subprocess.call("rm -R /etc/motd", shell=True)

    # disable user list for gdm3
    with open("/etc/dconf/profile/gdm", "w") as f:
        f.write("user-db:user\n")
        f.write("system-db:gdm\n")
        f.write("file-db:/usr/share/gdm/greeter-dconf-defaults\n")
    if not os.path.exists("/etc/dconf/db/gdm.d"):
        os.mkdir("/etc/dconf/db/gdm.d")
    with open("/etc/dconf/db/gdm.d/00-login-screen", "w") as f:
        f.write("[org/gnome/login-screen]\n")
        f.write("disable-user-list=true\n")
    subprocess.call("dconf update", shell=True)

    # disable guest account
    subprocess.call("usermod -L guest", shell=True)

    # disable media automount in GNOME
    if not os.path.exists("/etc/dconf/db/local.d"):
        os.mkdir("/etc/dconf/db/local.d")
    with open("/etc/dconf/db/local.d/00-media-automount", "w") as f:
        f.write("[org/gnome/desktop/media-handling]\n")
        f.write("automount=false\n")
        f.write("automount-open=false\n")
    subprocess.call("dconf update", shell=True)

    # ensure avahi server not installed
    subprocess.call("systemctl stop avahi-daaemon.service", shell=True)
    subprocess.call("systemctl stop avahi-daemon.socket", shell=True)
    subprocess.call("apt purge avahi-daemon", shell=True)

    configparser = ConfigParser()
    configparser.read("/etc/postfix/main.cf")
    # ensure mail transfer agent local only
    shutil.copy("clean_files/main.cf", "/etc/postfix/main.cf")

    # remove rsync
    subprocess.call("apt purge rsync", shell=True)

    # disable wireless interfaces (re-enable with nmcli radio wifi on)
    subprocess.call("nmcli radio wifi off", shell=True)

    # disable ipv4 redirects
    subprocess.call("/sbin/sysctl -w net.ipv4.conf.all.send_redirects=0", shell=True)

    # disable ip forwarding
    subprocess.call("/sbin/sysctl -w net.ipv4.ip_forward=0", shell=True)
    subprocess.call("/sbin/sysctl -w net.ipv6.conf.all.forwarding=0", shell=True)

    # firewall stuff in background
    print("Configuring firewall...")
    firewall = Process(target=firewall_config)
    firewall.start()

    # flushing dns caches in background
    print("Flushing dns...")
    dns = Process(target=dns_flush())
    dns.start()

    # scans in background
    # print("Running scans...")
    # scans = Process(target=scans)
    # scans.start()

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
    shutil.copy("/etc/login.defs", "backups/passconfig/login.defs")
    shutil.copy("clean_files/login.defs", "/etc/login.defs")
    # common-password
    shutil.copy("/etc/pam.d/common-password", "backups/passconfig/common-password")
    shutil.copy("clean_files/common-password", "/etc/pam.d/common-password")
    # common-auth
    shutil.copy("/etc/pam.d/common-auth", "backups/passconfig/common-auth")
    shutil.copy("clean_files/common-auth", "/etc/pam.d/common-auth")
    # common-account
    shutil.copy("/etc/pam.d/common-account", "backups/passconfig/common-account")
    shutil.copy("clean_files/common-account", "/etc/pam.d/common-account")

    # open passwd file and if users are not in users.txt or admins.txt, delete them
    with open('logs/user_changes.log', 'w') as user_changes:
        with open("/etc/passwd") as passwd:
            lines = passwd.readlines()
            for line_number, line in enumerate(lines):
                split = line.split(":")
                user = split[0].strip()
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
                if user != "root" and (uid == 0 or gid == 0):
                    lines[line_number] = "#" + line
                    print("commented out " + user + " because uid 0 and not root")
                    user_changes.write(user + " commented out because uid 0 and not root")
                    with open("/etc/passwd", "w") as passwdw:
                        passwdw.writelines(lines)

                # change user password
                subprocess.call('echo -e "Cyb3RP@tri0t\nCyb3RP@tri0t" | passwd ' + user, shell=True)

    # prevent network root logon
    subprocess.call("echo > /etc/securetty", shell=True)

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
    if os.path.isfile("/etc/init/control-alt-delete.conf"):
        with open("/etc/init/control-alt-delete.conf", "w") as control_alt_delete:
            control_alt_delete.write("start on control-alt-delete\ntask\nexec false")

    # clean copies of sudoers stuff
    shutil.copy("/etc/sudoers", "backups/sudoconfigs/sudoers")
    shutil.copy("clean_files/sudoers", "/etc/sudoers")
    shutil.copy("/etc/sudoers.d/README", "backups/sudoconfigs/README")
    shutil.copy("clean_files/README", "/etc/sudoers.d/README")

    # removes any sudo configurations
    for file in os.listdir("/etc/sudoers.d"):
        if file != "README":
            subprocess.call("mv /etc/sudoers.d/" + file + " backups/sudoconfigs/" + file, shell=True)

    # sysctl hardening
    shutil.copy("/etc/sysctl.conf", "backups/sysctl.conf")
    shutil.copy("clean_files/sysctl.conf", "/etc/sysctl.conf")

    # enable tcp syn cookies
    shutil.copy("/etc/sysctl.d/10-network-security.conf", "backups/10-network-security.conf")
    shutil.copy("clean_files/10-network-security.conf", "/etc/sysctl.d/10-network-security.conf")
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
    if os.path.isfile("/etc/ssh/sshd_config"):
        shutil.copy("/etc/ssh/sshd_config", "backups/sshd_config")
        shutil.copy("clean_files/sshd_config", "/etc/ssh/sshd_config")

    # harden apache
    if os.path.isfile("/etc/apache2"):
        shutil.copy("clean_files/apache2.conf", "/etc/apache2/apache2.conf")

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
            subprocess.call("mv /etc/cron.d/" + file + " backups/crontab/" + file, shell=True)

    # /etc/rc.local should be empty
    with open("/etc/rc.local", "w") as rc_local:
        rc_local.write("#!/bin/sh -e\nexit 0")

    # secure shared memory
    with open("/etc/fstab", "a+") as fstab:
        if "#already run" not in fstab.read():
            fstab.write("#already run\nnone     /run/shm     tmpfs     rw,noexec,nosuid,nodev     0     0")

    # remove bad programs
    package_arr = {"john": "john john-data", "telnetd": "openbsd-inetd telnetd", "logkeys": "logkeys",
                   "hydra": "hydra-gtk hydra", "fakeroot": "fakeroot",
                   "nmap": "nmap zenmap", "crack": "crack crack-common", "medusa": "libssh2-1 medusa", "nikto": "nikto",
                   "tightvnc": "xtightvncviewer", "bind9": "bind9 bind9utils",
                   "avahi": "avahi-autoipd avahi-daemon avahi-utils",
                   "cups": "cups cups-core-drivers printer-driver-hpcups indicator-printers printer-driver-splix "
                           "hplip printer-driver-gutenprint bluez-cups printer-driver-postscript-hp cups-server-common "
                           "cups-browsed cups-bsd cups-client cups-common cups-daemon cups-ppdc cups-filters "
                           "cups-filters-core-drivers printer-driver-pxljr printer-driver-foo2zjs foomatic-filters "
                           "cups-pk-helper",
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
                   "minetest": "minetest", "isc-dhcp-server": "isc-dhcp-server", "dhcp3-server": "dhcp3-server",
                   "slapd": "slapd", "nfs-kernel-server": "nfs-kernel-server", "dovecot-imapd": "dovecot-imapd",
                   "dovecot-pop3d": "dovecot-pop3d", "dovecot-common": "dovecot-common", "squid": "squid",
                   "snmp": "snmp", "nis": "nis", "rsh-client": "rsh-client", "talk": "talk", "telnet": "telnet",
                   "ldap-utils": "ldap-utils", "rpcbind": "rpcbind"}

    subprocess.call("dpkg-query -f '${binary:Package}\n' -W > packages_list.txt", shell=True)
    with open("packages_list.txt", "r") as packages_list:
        for installed_package in packages_list:
            for arr_list in package_arr.values():
                if installed_package.strip() in arr_list:
                    if ask("Remove " + installed_package + "?"):
                        subprocess.call("apt purge " + arr_list + " -y", shell=True)
                        subprocess.call("dpkg-query -f '${binary:Package}\n' -W > packages_list.txt", shell=True)
                        print("Removed " + installed_package)

    # with open('logs/sus_files.log', 'w') as suspicious_files:
    #     output = subprocess.check_output("timeout 60 find / -nouser -o -nogroup", shell=True, text=True)
    #     output += subprocess.check_output("timeout 60 find / -perm -2 ! -type l -ls", shell=True, text=True)
    #     suspicious_files.write(output)

    # change ownership of files
    subprocess.call("chown root:root /etc/securetty", shell=True)
    subprocess.call("chmod 0600 /etc/securetty", shell=True)
    subprocess.call("chmod 644 /etc/crontab", shell=True)
    subprocess.call("chmod 744 /etc/cron.daily", shell=True)
    subprocess.call("chmod 744 /etc/cron.hourly", shell=True)
    subprocess.call("chmod 744 /etc/cron.monthly", shell=True)
    subprocess.call("chmod 744 /etc/cron.weekly", shell=True)
    subprocess.call("chmod 744 /etc/cron.d", shell=True)
    with open("/etc/cron.allow", "w") as cron_allow:
        cron_allow.write("root")
    with open("/etc/at.allow", "w") as at_allow:
        at_allow.write("root")
    subprocess.call("chmod 644 /etc/cron.allow", shell=True)
    subprocess.call("chmod 644 /etc/at.allow", shell=True)
    subprocess.call("chmod 640 /etc/ftpusers", shell=True)
    subprocess.call("chmod 440 /etc/inetd.conf", shell=True)
    subprocess.call("chmod 440 /etc/xinetd.conf", shell=True)
    subprocess.call("chmod 400 /etc/inetd.d", shell=True)
    subprocess.call("chmod 644 /etc/hosts.allow", shell=True)
    subprocess.call("chmod 440 /etc/sudoers", shell=True)
    subprocess.call("chmod 640 /etc/shadow", shell=True)
    subprocess.call("chown root:root /etc/shadow", shell=True)
    subprocess.call("chmod u-x,g-wx,o-rwx /etc/shadow", shell=True)
    subprocess.call("chown root:root /etc/shadow-", shell=True)
    subprocess.call("chmod u-x,g-wx,o-rwx /etc/shadow-", shell=True)
    subprocess.call("chown root:root /etc/gshadow", shell=True)
    subprocess.call("chmod u-x,g-wx,o-rwx /etc/gshadow", shell=True)
    subprocess.call("chown root:root /etc/passwd", shell=True)
    subprocess.call("chmod u-x,go-wx /etc/passwd", shell=True)
    subprocess.call("chown root:root /etc/group", shell=True)
    subprocess.call("chmod u-x,go-wx /etc/group", shell=True)
    subprocess.call("chown root:root /etc/group-", shell=True)
    subprocess.call("chmod u-x,go-wx /etc/group-", shell=True)
    subprocess.call("chmod 644 /etc/issue", shell=True)
    subprocess.call("chmod 644 /etc/issue.net", shell=True)

    print("Waiting for background processes to finish...")
    firewall.join()
    dns.join()

    print(
        "Script finished. Check dpkg for other bad packages. Check for bad media files. Look for world writable files")


if __name__ == "__main__":
    test()
