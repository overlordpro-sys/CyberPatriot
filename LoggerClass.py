from datetime import datetime
class Logger:
    def __init__(self, filename):
        self.log_file = open(filename, 'a')

    def logH1(self, message):
        self.log_file.write(f"XX---- {message.upper()} ----XX")

    def logH2(self, message):
        self.log_file.write(f"------ {message} ------")

    def logChange(self, message):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.log_file.write(f"{timestamp} - {message}\n")

    def logHEnd(self):
        self.log_file.write("\n")

    def close(self):
        self.log_file.close()