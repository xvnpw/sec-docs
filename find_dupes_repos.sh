#!/bin/bash

# Check if a filename is provided
if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <filename>"
  exit 1
fi

filename=$1

# Check if the file exists
if [ ! -f "$filename" ]; then
  echo "File not found: $filename"
  exit 1
fi

# Declare an associative array to store repo names and their owners
declare -A repo_map

# Read the file line by line
while IFS= read -r line; do
  # Extract the URL from the line
  url=$(echo "$line" | awk '{print $2}')

  # Extract the repository owner and name
  if [[ $url =~ github\.com/([^/]+)/([^/]+) ]]; then
    owner=${BASH_REMATCH[1]}
    repo_name=${BASH_REMATCH[2]}

    # Check if the repository name is already in the map
    if [[ -v "repo_map[$repo_name]" ]]; then
      repo_map[$repo_name]="${repo_map[$repo_name]}, $owner"
    else
      repo_map[$repo_name]="$owner"
    fi
  fi
done < "$filename"

# Print duplicates
echo "Duplicate repositories found:"
found=false
for repo in "${!repo_map[@]}"; do
  owners=${repo_map[$repo]}
  if [[ $owners == *,* ]]; then
    echo "Repository '$repo' is owned by multiple users: $owners"
    found=true
  fi
done

if [ "$found" = false ]; then
  echo "No duplicate repositories found."
fi
