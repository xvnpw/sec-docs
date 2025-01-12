import json
import glob
import os
import argparse


def sum_token_usage(base_dir="."):
    # Find all output-metadata.json files recursively
    total_tokens = 0
    file_count = 0

    # Update the glob pattern to use base_dir
    pattern = os.path.join(base_dir, "**/output-metadata.json")
    for filepath in glob.glob(pattern, recursive=True):
        try:
            with open(filepath, "r") as f:
                data = json.load(f)

                # Check if the file has the required analyzer_args
                if "--deep-analysis" not in data.get("analyzer_args"):
                    # Convert token usage to integer and add to total
                    tokens = int(data.get("actual_token_usage", 0))
                    total_tokens += tokens
                    file_count += 1
                    print(f"Processing {filepath}: {tokens} tokens")

        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"Error processing {filepath}: {str(e)}")
            continue

    print(f"\nTotal files processed: {file_count}")
    print(f"Total token usage: {total_tokens}")
    return total_tokens


if __name__ == "__main__":
    # Add command line argument parsing
    parser = argparse.ArgumentParser(description="Sum token usage from output-metadata.json files")
    parser.add_argument("--base-dir", default=".", help="Base directory to search from (default: current directory)")
    args = parser.parse_args()

    sum_token_usage(args.base_dir)
