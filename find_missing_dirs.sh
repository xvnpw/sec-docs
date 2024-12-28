#!/bin/bash

# Base directory to search
BASE_DIR="./"

# Function to find top-level directories without subdirectories
find_missing_dirs() {
    find "$BASE_DIR" -mindepth 2 -maxdepth 2 -type d \( -path "$BASE_DIR/.git" -prune \) -o -type d | while read -r dir; do
        # Skip .git directories
        if [[ "$dir" == *".git"* ]]; then
            continue
        fi

        # Check if the directory contains any subdirectories
        subdirs=$(find "$dir" -mindepth 1 -maxdepth 1 -type d | wc -l)
        if [ "$subdirs" -eq 0 ]; then
            echo "Directory without subdirectories: $dir"
        fi
    done
}

# Execute the function
find_missing_dirs
