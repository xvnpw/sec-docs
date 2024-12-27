import os
import json
import shutil


def process_first_repo():
    # Read the first line and remaining lines
    with open("repos.txt", "r") as file:
        lines = file.readlines()
        if not lines:
            return False

        first_line = lines[0].strip()

    # Parse the first line
    language, repo_url = first_line.split(" ")

    # Create directory if it doesn't exist
    repo_name = repo_url.split("/")[-1]
    config_dir = os.path.join(language, repo_name)
    os.makedirs(config_dir, exist_ok=True)

    # Create config.json
    config = {
        "repo_url": repo_url,
        "analyzer_args": "",
        "agent_provider": "google",
        "agent_model": "gemini-2.0-flash-thinking-exp",
        "agent_temperature": 0.0,
        "agent_prompt_types": ["sec-design", "threat-modeling", "attack-surface", "attack-tree"],
    }

    # Write config.json
    config_path = os.path.join(config_dir, "config.json")
    with open(config_path, "w") as f:
        json.dump(config, f, indent=4)

    # Remove first line and write back remaining lines
    with open("repos.txt", "w") as file:
        file.writelines(lines[1:])

    return True


if __name__ == "__main__":
    process_first_repo()
