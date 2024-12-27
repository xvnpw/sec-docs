#!/usr/bin/env python3

import os
import json

SPONSORSHIP = """## Support **sec-docs**

**sec-docs** is an ambitious initiative aimed at enhancing the security of open-source software through AI-powered documentation. We need your support to continue and expand our analysis of major OSS projects.

### Why Your Support Matters

Open-source software drives much of the technology we rely on daily. However, inadequate security documentation leaves these projects vulnerable. **sec-docs** bridges this gap by:

- **Automatic Analysis:** Using advanced AI models to create tailored, comprehensive security documentation.
- **Simplifying Security:** Making complex security concepts understandable and actionable for developers.
- **Dynamic Updates:** Keeping documentation current as code evolves.

Your support enables more developers to build safer applications and strengthens trust in open-source ecosystems.

### The Cost of Innovation

Generating security documentation for just one project requires over **dozens of thousands of tokens**, costing around **~$15** per project. These expenses are incurred through:

1. **AI Model Access:** API calls and subscriptions to premium LLM services.

### How You Can Make a Difference

Your contributions will fuel the expansion of **sec-docs**, bringing vital security resources to more OSS projects. Together, we can enhance the security landscape of open-source software.

**Ways to Support:**
- **GitHub Sponsors:** Become a sponsor and directly support our ongoing efforts at [GitHub Sponsors](https://github.com/sponsors/xvnpw).

### Thank You

Your support is crucial to our mission and greatly appreciated by the global open-source community. Together, let's make open-source software safer, one project at a time.
"""

INTRODUCTION = """# sec-docs
Security documentation for important Open Source Software (OSS) projects, generated using LLM technology.

The documentation includes:
- 🔍 Attack surface analysis
- 🌳 Attack trees
- 🔒 Security design reviews
- 🎯 Threat modeling

## How to Navigate This Repository

**sec-docs** is organized by programming language, with folders for each major OSS project. Each project contains subfolders with detailed analyses performed at a specific date using a certain LLM model.

"""


def main():
    readme_lines = []
    exclude_dirs = {".git", ".github", "__pycache__"}
    exclude_files = {"README.md", "LICENSE", "generate_readme.py"}

    # Get the top-level directories (languages)
    languages = sorted([d for d in os.listdir(".") if os.path.isdir(d) and d not in exclude_dirs])
    for language in languages:
        # Add language header with link
        readme_lines.append(f"\n### [{language.title()}]({language}/)\n")

        # Add table header
        readme_lines.append("| Project | GitHub Link | Analysis Date | Documentation |")
        readme_lines.append("|---------|-------------|---------------|---------------|")

        language_dir = os.path.join(".", language)
        projects = sorted([p for p in os.listdir(language_dir) if os.path.isdir(os.path.join(language_dir, p))])

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

                # Split version string by first hyphen to separate date and model
                parts = version.split("-", 1)
                analysis_date = version[:10]
                model_info = f"<br>{version[11:]}"

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
                    f"| {project_link} | {source_repo_link} | {analysis_date} {model_info} | {', '.join(doc_links)} |"
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
