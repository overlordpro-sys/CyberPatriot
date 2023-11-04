import shutil
import subprocess

from LoggerClass import Logger


def general_config(logger: Logger):
    logger.logH1("GENERAL CONFIG")
    # sysctl hardening
    shutil.copy("/etc/sysctl.conf", "backups/sysctl.conf")
    shutil.copy("clean_files/sysctl.conf", "/etc/sysctl.conf")
    logger.logChange("Clean sysctl.config")

    # enable tcp syn cookies
    shutil.copy("/etc/sysctl.d/10-network-security.conf", "backups/10-network-security.conf")
    shutil.copy("clean_files/10-network-security.conf", "/etc/sysctl.d/10-network-security.conf")
    subprocess.call("sysctl --system", shell=True)
    logger.logChange("Clean 10-network-security.conf")

    # disable guest account
    subprocess.call("usermod -L guest", shell=True)
    logger.logChange("Disabled guest account")

    # disable ipv4 redirects
    subprocess.call("/sbin/sysctl -w net.ipv4.conf.all.send_redirects=0", shell=True)
    logger.logChange("Disabled ipv4 redirect")

    # disable ip forwarding
    subprocess.call("/sbin/sysctl -w net.ipv4.ip_forward=0", shell=True)
    subprocess.call("/sbin/sysctl -w net.ipv6.conf.all.forwarding=0", shell=True)
    logger.logChange("Disable ipv4 forwarding")

    logger.logHEnd()
