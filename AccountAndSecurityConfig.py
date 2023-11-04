import shutil

from LoggerClass import Logger


def password_config(logger: Logger):
    logger.logH1("PASSWORD CONFIG")

    logger.logH2("Login Defs")
    shutil.copy("/etc/login.defs", "backups/passconfig/login.defs")
    shutil.copy("clean_files/login.defs", "/etc/login.defs")
    logger.logHEnd()
