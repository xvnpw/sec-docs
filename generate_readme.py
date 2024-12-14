#!/usr/bin/env python3

import os
import json


def main():
    readme_lines = []
    readme_lines.append("# sec-docs")
    readme_lines.append("Security documentation for important OSS projects generated by LLM\n")

    exclude_dirs = {".git", ".github", "__pycache__"}
    exclude_files = {"README.md", "LICENSE", "generate_readme.py"}

    # Get the top-level directories (languages)
    languages = sorted([d for d in os.listdir(".") if os.path.isdir(d) and d not in exclude_dirs])
    for language in languages:
        language_link = f"[{language}]({language})"
        readme_lines.append(f"- {language_link}")
        language_dir = os.path.join(".", language)

        projects = sorted([p for p in os.listdir(language_dir) if os.path.isdir(os.path.join(language_dir, p))])
        for project in projects:
            project_dir = os.path.join(language_dir, project)
            project_link = f"[{project}]({language}/{project})"

            # Initialize source repo link
            source_repo_link = ""
            # Check for config.json in the project directory
            config_path = os.path.join(project_dir, "config.json")
            if os.path.isfile(config_path):
                with open(config_path, "r") as config_file:
                    config = json.load(config_file)
                    repo_url = config.get("repo_url", "").strip()
                    # If repo_url exists and is not empty, create the link
                    if repo_url:
                        source_repo_link = f" - [source repo]({repo_url})"

            readme_lines.append(f"  - {project_link}{source_repo_link}")

            versions = sorted([v for v in os.listdir(project_dir) if os.path.isdir(os.path.join(project_dir, v))])
            versions.sort(key=lambda x: (0, x) if x == "latest" else (1, x))
            for version in versions:
                version_dir = os.path.join(project_dir, version)
                version_link = f"[{version}]({language}/{project}/{version})"

                # List markdown files in version_dir
                md_files = sorted([f for f in os.listdir(version_dir) if f.endswith(".md")])
                links = []
                for md_file in md_files:
                    name = os.path.splitext(md_file)[0]
                    file_link = f"[{name}]({language}/{project}/{version}/{md_file})"
                    links.append(file_link)

                if links:
                    links_str = ", ".join(links)
                    readme_lines.append(f"    - {version_link} - {links_str}")
                else:
                    readme_lines.append(f"    - {version_link}")

    # Write to README.md
    with open("README.md", "w") as f:
        for line in readme_lines:
            f.write(line + "\n")


if __name__ == "__main__":
    main()
