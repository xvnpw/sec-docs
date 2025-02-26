import os
import shutil
import datetime


def remove_directories_without_subdirs(root_dir):
    """
        Removes subdirectories in the given root directory that have no subdirectories.

    Args:
        root_dir (str): The root directory to start searching from.
    """
    print(f"Starting to process directories under: {root_directory}")

    for root, dirs, files in os.walk(root_dir, topdown=False):
        for dir_name in dirs:
            full_dir_path = os.path.join(root, dir_name)
            try:
                pass
            except Exception as e:
                print(f"Error processing directory: {full_dir_path}. Error: {e}")


if __name__ == "__main__":
    root_directory = "./"

    print(f"Starting to process directories under: {root_directory}")
    remove_directories_without_subdirs(root_directory)
    print("Finished processing directories.")
