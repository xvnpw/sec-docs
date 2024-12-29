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


def main():
    readme_lines = []
    exclude_dirs = {".git", ".github", "__pycache__", ".data"}
    exclude_files = {"README.md", "LICENSE", "generate_readme.py"}

    # Get the top-level directories (languages)
    languages = sorted([d for d in os.listdir(".") if os.path.isdir(d) and d not in exclude_dirs])
    for language in languages:
        # Add language header with link
        readme_lines.append(f"\n### [{language.title()}]({language}/)\n")

        # Add table header
        readme_lines.append("| Project | Analysis Date | Documentation |")
        readme_lines.append("|---------|-------------|---------------|")

        language_dir = os.path.join(".", language)
        projects = sorted(
            [p for p in os.listdir(language_dir) if os.path.isdir(os.path.join(language_dir, p))], key=str.lower
        )

        for project in projects:
            project_dir = os.path.join(language_dir, project)

            # Get GitHub link
            source_repo_link = ""
            config_path = os.path.join(project_dir, "config.json")
            if os.path.isfile(config_path):
                with open(config_path, "r") as config_file:
                    config = json.load(config_file)
                    repo_url = config.get("repo_url", "").strip()
                    if repo_url:
                        source_repo_link = f"[GitHub]({repo_url})"

            versions = sorted(
                [v for v in os.listdir(project_dir) if os.path.isdir(os.path.join(project_dir, v))], reverse=True
            )

            for version in versions:
                version_dir = os.path.join(project_dir, version)

                analysis_date = version[:10]
                model_info = version[11:]

                # Get documentation links
                doc_types = {
                    "sec-design.md": "Security Design Review",
                    "threat-modeling.md": "Threat Modeling",
                    "attack-surface.md": "Attack Surface",
                    "attack-tree.md": "Attack Tree",
                }

                doc_links = []
                for doc_file, doc_name in doc_types.items():
                    if os.path.exists(os.path.join(version_dir, doc_file)):
                        doc_links.append(f"[{doc_name}]({language}/{project}/{version}/{doc_file})")

                # Create table row with project link
                project_link = f"[**{project}**]({language}/{project}/)"
                table_row = (
                    f"| {project_link} ({source_repo_link}) | {analysis_date} {model_info} | {', '.join(doc_links)} |"
                )
                readme_lines.append(table_row)

    # Write to README.md
    with open("README.md", "w") as f:
        f.write(INTRODUCTION + "\n")
        for line in readme_lines:
            f.write(line + "\n")
        f.write("\n" + SPONSORSHIP)


if __name__ == "__main__":
    main()
