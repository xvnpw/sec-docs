import os
import json
import shutil
import tempfile
from urllib.parse import urlparse


def reorganize_files(root_dir):
    """
    Reorganizes files based on the content of config.json files using a temporary directory.

    Args:
        root_dir: The root directory to start the search from.
    """
    with tempfile.TemporaryDirectory() as tmp_root:
        # Copy the original directory structure to the temporary directory
        shutil.copytree(root_dir, tmp_root, dirs_exist_ok=True)
        print(f"Copied original structure to temporary directory: {tmp_root}")

        moved_directories = set()
        config_files_data = []

        # First pass: Collect information from config.json files in the temporary directory
        for dirpath, dirnames, filenames in os.walk(tmp_root):
            if "config.json" in filenames:
                config_path = os.path.join(dirpath, "config.json")
                try:
                    with open(config_path, "r") as f:
                        config_data = json.load(f)

                    repo_url = config_data.get("repo_url")
                    if not repo_url:
                        print(f"Warning: 'repo_url' not found in {config_path}. Skipping.")
                        continue

                    parsed_url = urlparse(repo_url)
                    path_segments = parsed_url.path.strip("/").split("/")
                    if not path_segments:
                        print(
                            f"Warning: Could not parse organization and repo name from '{repo_url}' in {config_path}. Skipping."
                        )
                        continue

                    if len(path_segments) >= 2:
                        org_name = path_segments[-2].lower()
                        repo_name = path_segments[-1].lower()
                    else:
                        print(
                            f"Warning: Could not reliably parse organization and repo name from '{repo_url}' in {config_path}. Skipping."
                        )
                        continue

                    # Extract the experiment directory name (relative to tmp_root)
                    relative_dirpath = os.path.relpath(dirpath, tmp_root)
                    experiment_dir_name = os.path.basename(relative_dirpath)

                    config_files_data.append(
                        {
                            "config_path_original": os.path.join(root_dir, relative_dirpath, "config.json"),
                            "dirpath_tmp": dirpath,
                            "org_name": org_name,
                            "repo_name": repo_name,
                            "experiment_dir_name": experiment_dir_name,
                        }
                    )

                except FileNotFoundError:
                    print(f"Error: config.json not found at {config_path}")
                except json.JSONDecodeError:
                    print(f"Error: Could not decode JSON in {config_path}")
                except Exception as e:
                    print(f"An error occurred while processing {config_path}: {e}")

        shutil.rmtree(root_dir)

        # Second pass: Move files based on the collected information
        for data in config_files_data:
            config_path_tmp = os.path.join(data["dirpath_tmp"], "config.json")
            relative_original_dir = os.path.relpath(os.path.dirname(data["config_path_original"]), root_dir)
            original_dir_path = os.path.join(root_dir, relative_original_dir)

            new_base_dir = os.path.join(root_dir, data["org_name"], data["repo_name"])
            new_config_path = os.path.join(new_base_dir, "config.json")

            os.makedirs(os.path.dirname(new_config_path), exist_ok=True)
            shutil.move(config_path_tmp, new_config_path)
            print(f"Moved: {config_path_tmp} -> {new_config_path}")

            # Move other files from the original location to the new location
            for filename in os.listdir(data["dirpath_tmp"]):
                if filename != "config.json":
                    old_file_path = os.path.join(data["dirpath_tmp"], filename)
                    new_file_path = os.path.join(new_base_dir, filename.lower())
                    os.makedirs(os.path.dirname(new_file_path), exist_ok=True)
                    shutil.move(old_file_path, new_file_path)
                    print(f"Moved: {old_file_path} -> {new_file_path}")


if __name__ == "__main__":
    exclude_dirs = {".git", ".github", "__pycache__", ".data", ".scripts"}

    # Get the top-level directories (languages)
    root_dirs = sorted([d for d in os.listdir(".") if os.path.isdir(d) and d not in exclude_dirs])
    for root_dir in root_dirs:
        reorganize_files(root_dir)
    print("File reorganization and empty directory removal complete.")
