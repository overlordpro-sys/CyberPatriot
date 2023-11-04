import shutil
from Util import backup_then_clean_file
from LoggerClass import Logger


def password_config(logger: Logger):
    logger.logH1("PASSWORD CONFIG")

    logger.logH2("Login Defs")
    backup_then_clean_file(abs_path="/etc/login.defs", file_name="login.defs")
    logger.logHEnd()
