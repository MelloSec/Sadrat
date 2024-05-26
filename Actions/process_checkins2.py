import os

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

def process_agents(script_lines):
    agent_folders = get_agent_folders()
    uninitialized_found = False

    for agent in agent_folders:
        age_file = os.path.join(AGENTS_PATH, agent, 'age.txt')
        checkin_file = os.path.join(AGENTS_PATH, agent, 'checkin.txt')

        if os.path.exists(age_file) and not os.path.exists(checkin_file):
            if script_lines:
                command = script_lines.pop(0)
                write_command_to_checkin(agent, command)
                print(f"Initialized check-in for {agent} with command: {command.strip()}")
                uninitialized_found = True
                break
            else:
                print("No more commands in script.txt to assign")
                break

    if not uninitialized_found:
        print("No uninitialized agents found")

    return script_lines

def main():
    script_lines = read_script()
    script_lines = process_agents(script_lines)

if __name__ == "__main__":
    main()
