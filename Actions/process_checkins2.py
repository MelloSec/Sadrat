import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

REPO_PATH = os.getenv('GITHUB_WORKSPACE', '.')
SCRIPT_FILE = os.path.join(REPO_PATH, 'script.txt')
AGENTS_PATH = REPO_PATH  # Assuming the agents check-in folders are in the root of the repo

def read_script():
    with open(SCRIPT_FILE, 'r') as file:
        return file.readlines()

def get_agent_folders():
    return [f for f in os.listdir(AGENTS_PATH) if os.path.isdir(os.path.join(AGENTS_PATH, f)) and not f.startswith('.')]

def write_command_to_checkin(agent, command):
    checkin_file = os.path.join(AGENTS_PATH, agent, 'checkin.txt')
    with open(checkin_file, 'w') as file:
        file.write(command)

def process_agent(agent, script_lines):
    checkin_file = os.path.join(AGENTS_PATH, agent, 'checkin.txt')
    if not os.path.exists(checkin_file) or os.path.getsize(checkin_file) == 0:
        if script_lines:
            command = script_lines.pop(0)
            write_command_to_checkin(agent, command)
            print(f"Initialized check-in for {agent} with command: {command.strip()}")
        else:
            print("No more commands in script.txt to assign")
    else:
        print(f"Agent {agent} already has a command or is processing")

    return script_lines

class AgentEventHandler(FileSystemEventHandler):
    def __init__(self, script_lines):
        self.script_lines = script_lines

    def on_created(self, event):
        if event.is_directory:
            return
        if os.path.basename(event.src_path) == 'age.txt':
            agent_folder = os.path.basename(os.path.dirname(event.src_path))
            self.script_lines = process_agent(agent_folder, self.script_lines)

def main():
    script_lines = read_script()
    event_handler = AgentEventHandler(script_lines)
    observer = Observer()
    observer.schedule(event_handler, path=AGENTS_PATH, recursive=True)
    observer.start()
    print("Monitoring for new agent check-ins...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()
