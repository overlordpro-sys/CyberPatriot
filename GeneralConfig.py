import shutil
import subprocess

from LoggerClass import Logger


def general_config(logger: Logger):
    logger.logH1("GENERAL CONFIG")
    # enable ipv4, ipv6 hardening
    shutil.copy("/etc/sysctl.conf", "backups/sysctl.conf")
    shutil.copy("clean_files/sysctl.conf", "/etc/sysctl.conf")
    logger.logChange("Clean sysctl.config")

    shutil.copy("/etc/sysctl.d/10-network-security.conf", "backups/10-network-security.conf")
    shutil.copy("clean_files/10-network-security.conf", "/etc/sysctl.d/10-network-security.conf")
    subprocess.call("sysctl --system", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    logger.logChange("Clean 10-network-security.conf")

    # disable guest account
    subprocess.call("usermod -L guest", shell=True)
    logger.logChange("Disabled guest account")

    logger.logChange("Disabled ipv4 redirect")

    logger.logHEnd()
