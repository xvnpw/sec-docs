import os
import argparse
import json
from urllib.parse import urlparse


def extract_repo_name(url):
    """Extracts the repository name from a GitHub URL."""
    path = urlparse(url).path.strip("/")
    return f"{path.split('/')[-2]}/{path.split('/')[-1]}"


def find_extra_repositories(input_file, base_dir):
    """
    Checks for extra repositories in a potentially nested directory structure.
    """
    expected_repositories = set()
    try:
        with open(input_file, "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) == 2:
                    repo_url = parts[1]
                    repo_name = extract_repo_name(repo_url)
                    expected_repositories.add(f"{parts[0]}/{repo_name}")
    except FileNotFoundError:
        print(f"Error: Input file not found.")
        return

    found_repositories = set()

    exclude_dirs = {".git", ".github", "__pycache__", ".data", ".scripts"}

    if os.path.isdir(base_dir):
        for lang_dir in os.listdir(base_dir):
            if lang_dir in exclude_dirs:
                continue
            lang_path = os.path.join(base_dir, lang_dir)
            if os.path.isdir(lang_path):
                for org_dir in os.listdir(lang_path):
                    org_path = os.path.join(lang_path, org_dir)
                    if os.path.isdir(org_path):
                        # Assuming the repository name is the next level down
                        for repo_dir in os.listdir(org_path):
                            found_repositories.add(f"{lang_dir}/{org_dir}/{repo_dir}")
    else:
        print(f"Error: Base directory not found.")
        return

    extra_repositories = found_repositories - expected_repositories

    if extra_repositories:
        for repo in sorted(extra_repositories):
            print(f"{repo}")
    else:
        print("No extra repositories found in the directory structure.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check for extra repositories in a directory structure.")
    parser.add_argument("input_file", help="Path to the input file.")
    parser.add_argument("base_dir", help="Path to the base directory to check.")
    args = parser.parse_args()

    find_extra_repositories(args.input_file, args.base_dir)
