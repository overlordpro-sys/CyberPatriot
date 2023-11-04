import os
import subprocess

import psutil

from LoggerClass import Logger


def remove_backdoors(logger: Logger):
    logger.logH1("BACKDOORS")

    logger.logH2("Remove netcat backdoors")
    for proc in psutil.process_iter(['name', 'pid', 'exe']):
        if proc.name() == "nc" or proc.name() == "netcat" or proc.name() == "ncat":
            name = proc.info['name']
            pid = str(proc.info['pid'])
            exe = proc.info['exe']
            subprocess.call(str("cp " + exe + " backups/" + exe.rsplit('/')[-1]), shell=True)
            subprocess.call("rm " + exe, shell=True)
            subprocess.call("kill -9 " + pid, shell=True)
            logger.logChange(f"Removed and backed up {name} - {exe}")

    logger.logH2("Remove cronjobs")
    for file in os.listdir("/etc/cron.d"):
        if file != "README":
            subprocess.call("mv /etc/cron.d/" + file + " backups/crontab/" + file, shell=True)
            logger.logChange(f"Moved {file} cronjob")

    logger.logHEnd()
