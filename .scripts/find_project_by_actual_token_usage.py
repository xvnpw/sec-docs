#!/usr/bin/env python3
import json
import sys
import os
import argparse
from pathlib import Path


def find_matching_repos(root_dir, token_threshold):
    """
    Find all output-metadata.json files with mode='dir' and actual_token_usage < threshold

    Args:
        root_dir: Directory to start search from
        token_threshold: Maximum token usage value to filter by

    Returns:
        List of repo_urls meeting the criteria
    """
    matching_repos = []

    # Recursively find all output-metadata.json files
    for filepath in Path(root_dir).rglob("output-metadata.json"):
        try:
            with open(filepath, "r") as file:
                data = json.load(file)

                # Check if file contains required fields
                if "mode" in data and data["mode"] == "dir" and "actual_token_usage" in data:
                    # Convert token usage to int for comparison
                    try:
                        token_usage = int(data["actual_token_usage"].replace('"', ""))
                        if token_usage < token_threshold and "repo_url" in data:
                            matching_repos.append(f"{data['repo_url']} {token_usage}")
                    except ValueError:
                        # Skip if token_usage can't be converted to int
                        continue
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error processing {filepath}: {e}", file=sys.stderr)

    return matching_repos


def main():
    parser = argparse.ArgumentParser(description="Find repositories with specified token usage criteria")
    parser.add_argument("token_threshold", type=int, help="Maximum token usage threshold")
    parser.add_argument("--dir", default=".", help="Root directory to search (default: current directory)")

    args = parser.parse_args()

    matching_repos = find_matching_repos(args.dir, args.token_threshold)

    if matching_repos:
        for repo in matching_repos:
            print(repo)
    else:
        print("No matching repositories found.")


if __name__ == "__main__":
    main()
