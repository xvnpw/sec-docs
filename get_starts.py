import requests
import argparse
import os


def main():
    parser = argparse.ArgumentParser(description="Check GitHub repository stars.")
    parser.add_argument("filename", help="File containing list of repositories")
    parser.add_argument("-n", type=int, required=True, help="Star count threshold")
    args = parser.parse_args()

    filename = args.filename
    threshold = args.n

    # Get GITHUB_TOKEN from environment variables
    github_token = os.environ.get("GITHUB_TOKEN")

    # Prepare headers for requests
    headers = {}
    if github_token:
        headers["Authorization"] = f"token {github_token}"

    with open(filename, "r") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue  # Skip empty lines

            parts = line.split()
            if len(parts) < 2:
                print(f"Skipping invalid line: {line}")
                continue

            language, url = parts[0], parts[1]

            # Extract owner and repo name from URL
            try:
                # Assuming URL is in the format https://github.com/owner/repo
                url_parts = url.strip().split("/")
                owner = url_parts[3]
                repo = url_parts[4]
            except IndexError:
                print(f"Invalid repository URL format: {url}")
                continue

            api_url = f"https://api.github.com/repos/{owner}/{repo}"

            try:
                response = requests.get(api_url, headers=headers)
                if response.status_code == 200:
                    repo_data = response.json()
                    stars = repo_data.get("stargazers_count", 0)
                    archived = repo_data.get("archived", False)
                    if stars < threshold or archived:
                        print(f"{language} {url} {stars} {archived}")
                else:
                    print(f"Failed to fetch data for {url}: HTTP {response.status_code}")
            except requests.RequestException as e:
                print(f"Request error for {url}: {e}")


if __name__ == "__main__":
    main()
