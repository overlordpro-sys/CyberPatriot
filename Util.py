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