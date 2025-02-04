import os
import shutil
import datetime


def remove_directories_before_date(root_dir, cutoff_date_str):
    """
    Removes subdirectories in the given root directory that have a date in their name
    older than the specified cutoff date.

    Args:
        root_dir (str): The root directory to start searching from.
        cutoff_date_str (str): The cutoff date in YYYY-MM-DD format.
                               Subdirectories with dates before this date will be removed.
    """
    cutoff_date = datetime.datetime.strptime(cutoff_date_str, "%Y-%m-%d").date()
    print(f"Cutoff date: {cutoff_date}")

    for root, dirs, files in os.walk(root_dir, topdown=False):
        for dir_name in dirs:
            full_dir_path = os.path.join(root, dir_name)
            try:
                date_str_part = dir_name[:10]  # Assuming date is at the beginning and 10 chars long (YYYY-MM-DD)
                dir_date = datetime.datetime.strptime(date_str_part, "%Y-%m-%d").date()

                if dir_date < cutoff_date:
                    print(f"Deleting directory: {full_dir_path} with date: {dir_date}")
                    shutil.rmtree(full_dir_path)
                else:
                    print(f"Keeping directory: {full_dir_path} with date: {dir_date}")

            except ValueError:
                # If the directory name does not start with a date, ignore it
                pass
            except Exception as e:
                print(f"Error processing directory: {full_dir_path}. Error: {e}")


if __name__ == "__main__":
    root_directory = "./yaml"
    cutoff_date = "2025-01-26"

    print(f"Starting to process directories under: {root_directory}")
    remove_directories_before_date(root_directory, cutoff_date)
    print("Finished processing directories.")
