#!/usr/bin/env python3

import os
import json

SPONSORSHIP = """## Support **sec-docs**  

**sec-docs** is an ambitious project that enhances open-source software security through AI-powered documentation. We analyze major OSS projects to provide comprehensive security insights that help developers build more secure applications.

### Why This Project Matters  

Open-source software powers much of today's digital infrastructure, but security documentation is often incomplete, inconsistent, or outdated. This can leave projects vulnerable to attacks, misconfigurations, and other security risks.  

**sec-docs** solves this problem by leveraging advanced AI models to:  
- Automatically analyze OSS projects to create comprehensive, tailored security documentation.  
- Simplify complex security concepts, making them accessible to a wider audience of developers.  
- Update documentation dynamically as codebases evolve.  

This effort empowers developers to secure their projects more effectively and enhances trust in open-source software.  

### Why We Need Your Support  

Using large language models like **o1** and **o1-pro** incurs high costs. To generate meaningful documentation for just one project, the process consumes over **over dozens of thousands of tokens**, leading to substantial expenses. About **~15$** per project.  

Here's what your support will help fund:  
1. **AI Model Access**: Covering the costs of API calls and subscriptions to premium LLM services.  

### How You Can Help  

Your contributions will enable **sec-docs** to expand its reach and deliver critical security documentation to more OSS projects. Together, we can make open-source software safer for everyone.  

Consider sponsoring the project through:  
- **GitHub Sponsors** (https://github.com/sponsors/xvnpw)   

### Thank You  

Your support means the world to us and the broader open-source community. Let's work together to make open-source software more secure, one project at a time.
"""

INTRODUCTION = """# sec-docs
Security documentation for important Open Source Software (OSS) projects, generated using LLM technology.

This repository contains comprehensive security analysis and documentation for various popular open-source projects. The documentation includes:
- 🔍 Attack surface analysis
- 🌳 Attack trees
- 🔒 Security design reviews
- 🎯 Threat modeling
"""


def main():
    readme_lines = []

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
                        source_repo_link = f" - [github]({repo_url})"

            readme_lines.append(f"  - {project_link}{source_repo_link}")

            versions = sorted([v for v in os.listdir(project_dir) if os.path.isdir(os.path.join(project_dir, v))])
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
        f.write(INTRODUCTION + "\n")

        for line in readme_lines:
            f.write(line + "\n")

        f.write("\n" + SPONSORSHIP)


if __name__ == "__main__":
    main()
