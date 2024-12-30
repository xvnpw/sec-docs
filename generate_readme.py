#!/usr/bin/env python3

import os
import json

SPONSORSHIP = """## ⚠️ Known Limitations

- Documentation accuracy varies by model and project
- Some formatting issues exist (diagrams, tables)
- Security recommendations need expert validation
- Model responses may contain inaccuracies
- Documentation was generated based on the model's capabilities at the time of the **cut off date**

## 🤝 How to Contribute

Help us improve by:
1. Reviewing documentation and reporting inaccuracies
2. Suggesting better LLM models to test
3. Recommending documentation improvements
4. Sharing which document types you find most useful

### Reporting Issues
Create issues with:
- Label `model-evaluation` for LLM model feedback
- Label `doc-type-feedback` for document type evaluation
- Label `content` for accuracy concerns
- Label `formatting` for layout problems

[Create New Issue](https://github.com/xvnpw/sec-docs/issues/new)

## 💝 Support the Project

This research requires access to various AI models and computing resources. Support our work through:
- [GitHub Sponsors](https://github.com/sponsors/xvnpw)
- Contributing feedback and improvements

Your support helps us evaluate more models and improve documentation quality for the OSS community.
"""

INTRODUCTION = """# sec-docs
An experimental project using LLM technology to generate security documentation for Open Source Software (OSS) projects.

## 🔍 Project Overview

We're exploring how different LLM models can help create comprehensive security documentation including:
- Attack surface analysis
- Attack trees
- Security design reviews
- Threat modeling

## 🧪 Experimental Status

This is an early-phase research project currently testing:
- Gemini 2.0 Flash Thinking Experimental - model cut off date: **end of October 2023**
- Other LLM models (planned)

### Help Us Evaluate!
We need community help to determine:
1. Which LLM models produce the most accurate security documentation
2. Which types of security documents are most valuable
3. How to improve documentation quality and reliability

## How to Navigate This Repository

**sec-docs** is organized by programming language, with folders for each major OSS project. Each project contains subfolders with detailed analyses performed at a specific date using a certain LLM model.

### Current Projects
"""


def get_github_link(project_dir):
    config_path = os.path.join(project_dir, "config.json")
    if os.path.isfile(config_path):
        with open(config_path, "r") as config_file:
            config = json.load(config_file)
            return config.get("repo_url", "")
    return ""


def generate_main_readme(languages):
    readme_lines = [INTRODUCTION]

    for language in languages:
        readme_lines.append(f"\n### [{language.title()}]({language}/)\n")
        for owner in languages[language]:
            for project in languages[language][owner]:
                github_link = get_github_link(os.path.join(language, owner, project))
                github_part = f"[GitHub]({github_link})" if github_link else ""
                readme_lines.append(f"- [{owner}/{project}]({language}/{owner}/{project}) ({github_part})")

    readme_lines.append("\n" + SPONSORSHIP)

    with open("README.md", "w") as f:
        f.write("\n".join(readme_lines))


def main():
    exclude_dirs = {".git", ".github", "__pycache__", ".data"}
    exclude_files = {"README.md", "LICENSE", "generate_readme.py"}

    languages = {}

    top_dirs = [d for d in os.listdir(".") if os.path.isdir(d) and d not in exclude_dirs]

    for language in top_dirs:
        languages[language] = {}
        language_dir = os.path.join(".", language)

        owners = [o for o in os.listdir(language_dir) if os.path.isdir(os.path.join(language_dir, o))]
        for owner in owners:
            languages[language][owner] = {}
            owner_dir = os.path.join(language_dir, owner)

            projects = [p for p in os.listdir(owner_dir) if os.path.isdir(os.path.join(owner_dir, p))]
            for project in projects:
                project_dir = os.path.join(owner_dir, project)

                versions = sorted(
                    [v for v in os.listdir(project_dir) if os.path.isdir(os.path.join(project_dir, v))], reverse=True
                )

                version_lines = []
                language_version_lines = []  # Separate lines for language README
                for version in versions:
                    version_dir = os.path.join(project_dir, version)

                    analysis_date = version[:10]
                    model_name = version[11:]

                    doc_types = {
                        "sec-design.md": "Security Design Review",
                        "threat-modeling.md": "Threat Modeling",
                        "attack-surface.md": "Attack Surface",
                        "attack-tree.md": "Attack Tree",
                    }

                    # Project README doc links (relative to project directory)
                    project_doc_links = []
                    # Language README doc links (relative to language directory)
                    language_doc_links = []

                    for doc_file, doc_name in doc_types.items():
                        if os.path.exists(os.path.join(version_dir, doc_file)):
                            project_doc_links.append(f"[{doc_name}]({version}/{doc_file})")
                            language_doc_links.append(f"[{doc_name}]({owner}/{project}/{version}/{doc_file})")

                    version_lines.append(f"| {analysis_date} | {model_name} | {', '.join(project_doc_links)} |")
                    language_version_lines.append(
                        f"| {analysis_date} | {model_name} | {', '.join(language_doc_links)} |"
                    )

                languages[language][owner][project] = {
                    "project_lines": version_lines,
                    "language_lines": language_version_lines,
                }

                # Generate project README
                generate_project_readme(language, owner, project, version_lines)

        # Generate language README with the correct paths
        generate_language_readme(language, languages[language])

    generate_main_readme(languages)


def generate_language_readme(language, projects):
    readme_lines = [f"# {language.title()} Projects"]
    readme_lines.append("| Project | Analysis Date | Model | Documentation |")
    readme_lines.append("|---------|---------------|-------|---------------|")

    for owner in projects:
        for project, data in projects[owner].items():
            github_link = get_github_link(os.path.join(language, owner, project))
            project_name = f"[{owner}/{project}]({owner}/{project}/)"
            if github_link:
                project_name += f" ([GitHub]({github_link}))"

            for version_line in data["language_lines"]:
                parts = version_line.split("|")
                if len(parts) >= 4:
                    date = parts[1].strip()
                    model = parts[2].strip()
                    docs = parts[3].strip()
                    readme_lines.append(f"| {project_name} | {date} | {model} | {docs} |")

    with open(os.path.join(language, "README.md"), "w") as f:
        f.write("\n".join(readme_lines))


def generate_project_readme(language, owner, project, versions):
    readme_lines = [f"# {project.title()} Analysis"]

    github_link = get_github_link(os.path.join(language, owner, project))
    if github_link:
        readme_lines.append(f"\n[GitHub Repository]({github_link})\n")

    readme_lines.append("| Analysis Date | Model | Documents |")
    readme_lines.append("|---------------|-------|-----------|")
    readme_lines.extend(versions)

    project_dir = os.path.join(language, owner, project)
    with open(os.path.join(project_dir, "README.md"), "w") as f:
        f.write("\n".join(readme_lines))


if __name__ == "__main__":
    main()
