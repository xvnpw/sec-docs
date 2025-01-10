import os
import argparse
import json
from urllib.parse import urlparse


def extract_repo_name(url):
    """Extracts the repository name from a GitHub URL."""
    path = urlparse(url).path.strip("/")
    return f"{path.split('/')[-2]}/{path.split('/')[-1]}"


def check_directory_structure(input_file, base_dir):
    """
    Checks if the directory structure and files match the information in the input file.

    Args:
        input_file (str): Path to the input file.
        base_dir (str): Path to the base directory to check.
    """

    with open(input_file, "r") as f:
        lines = f.readlines()

    print(f"Checking {len(lines)} repositories...")

    for line in lines:
        parts = line.strip().split()
        if len(parts) != 2:
            print(f"Skipping invalid line: {line.strip()}")
            continue

        lang, repo_url = parts
        repo_name = extract_repo_name(repo_url)
        repo_dir = os.path.join(base_dir, lang, repo_name)

        # Check if directory exists
        if not os.path.isdir(repo_dir):
            print(f"  Missing: {line.strip()}")
            continue

        # Check for config.json and if it's not empty
        config_file = os.path.join(repo_dir, "config.json")
        if not os.path.isfile(config_file):
            print(f"  Error: 'config.json' not found in '{repo_dir}'.")
        else:
            if os.stat(config_file).st_size == 0:
                print(f"  Error: 'config.json' in '{repo_dir}' is empty.")

        # Check for at least one subdirectory
        has_subdirectory = any(
            os.path.isdir(os.path.join(repo_dir, item)) for item in os.listdir(repo_dir) if item != "config.json"
        )
        if not has_subdirectory:
            print(f"  Error: No subdirectories found in '{repo_dir}'.")
        else:
            # Check for specific files in subdirectories
            required_files = [
                "threat-modeling.md",
                "attack-surface.md",
                "attack-tree.md",
                "sec-design.md",
                "output-metadata.json",
            ]
            subdirectories = [item for item in os.listdir(repo_dir) if os.path.isdir(os.path.join(repo_dir, item))]
            if len(subdirectories) < 2:
                print(f"  Error: Only {len(subdirectories)} subdirectories found in '{repo_dir}'.")

            for item in subdirectories:
                subdir_path = os.path.join(repo_dir, item)
                if os.path.isdir(subdir_path):
                    missing_files = [f for f in required_files if not os.path.isfile(os.path.join(subdir_path, f))]
                    if missing_files:
                        print(f"    Error: Missing files in subdirectory '{item}': {', '.join(missing_files)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check directory structure against an input file.")
    parser.add_argument("input_file", help="Path to the input file.")
    parser.add_argument("base_dir", help="Path to the base directory to check.")
    args = parser.parse_args()

    check_directory_structure(args.input_file, args.base_dir)
