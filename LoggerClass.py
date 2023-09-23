class Logger:
    def __init__(self, filename):
        self.log_file = open(filename, 'a')

    def log(self, message):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.log_file.write(f"{timestamp} - {message}\n")

    def close(self):
        self.log_file.close()