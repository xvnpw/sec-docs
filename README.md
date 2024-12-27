# sec-docs
Security documentation for important Open Source Software (OSS) projects, generated using LLM technology.

This repository contains comprehensive security analysis and documentation for various popular open-source projects. The documentation includes:
- 🔍 Attack surface analysis
- 🌳 Attack trees
- 🔒 Security design reviews
- 🎯 Threat modeling

---

- [go](go)
  - [frp](go/frp) - [github link](https://github.com/fatedier/frp)
    - [2024-12-27-gemini-2.0-flash-thinking-exp](go/frp/2024-12-27-gemini-2.0-flash-thinking-exp) - [attack-surface](go/frp/2024-12-27-gemini-2.0-flash-thinking-exp/attack-surface.md), [attack-tree](go/frp/2024-12-27-gemini-2.0-flash-thinking-exp/attack-tree.md), [sec-design](go/frp/2024-12-27-gemini-2.0-flash-thinking-exp/sec-design.md), [threat-modeling](go/frp/2024-12-27-gemini-2.0-flash-thinking-exp/threat-modeling.md)
  - [gin](go/gin) - [github link](https://github.com/gin-gonic/gin)
    - [2024-12-27-gemini-2.0-flash-thinking-exp](go/gin/2024-12-27-gemini-2.0-flash-thinking-exp) - [attack-surface](go/gin/2024-12-27-gemini-2.0-flash-thinking-exp/attack-surface.md), [attack-tree](go/gin/2024-12-27-gemini-2.0-flash-thinking-exp/attack-tree.md), [sec-design](go/gin/2024-12-27-gemini-2.0-flash-thinking-exp/sec-design.md), [threat-modeling](go/gin/2024-12-27-gemini-2.0-flash-thinking-exp/threat-modeling.md)
- [java](java)
  - [micronaut-security](java/micronaut-security) - [github link](https://github.com/micronaut-projects/micronaut-security)
    - [2024-12-27-gemini-2.0-flash-thinking-exp](java/micronaut-security/2024-12-27-gemini-2.0-flash-thinking-exp) - [attack-surface](java/micronaut-security/2024-12-27-gemini-2.0-flash-thinking-exp/attack-surface.md), [attack-tree](java/micronaut-security/2024-12-27-gemini-2.0-flash-thinking-exp/attack-tree.md), [sec-design](java/micronaut-security/2024-12-27-gemini-2.0-flash-thinking-exp/sec-design.md), [threat-modeling](java/micronaut-security/2024-12-27-gemini-2.0-flash-thinking-exp/threat-modeling.md)
  - [xxl-job](java/xxl-job) - [github link](https://github.com/xuxueli/xxl-job)
    - [2024-12-27-gemini-2.0-flash-thinking-exp](java/xxl-job/2024-12-27-gemini-2.0-flash-thinking-exp) - [attack-surface](java/xxl-job/2024-12-27-gemini-2.0-flash-thinking-exp/attack-surface.md), [attack-tree](java/xxl-job/2024-12-27-gemini-2.0-flash-thinking-exp/attack-tree.md), [sec-design](java/xxl-job/2024-12-27-gemini-2.0-flash-thinking-exp/sec-design.md), [threat-modeling](java/xxl-job/2024-12-27-gemini-2.0-flash-thinking-exp/threat-modeling.md)
- [javascript](javascript)
  - [axios](javascript/axios) - [github link](https://github.com/axios/axios)
    - [2024-12-27-gemini-2.0-flash-thinking-exp](javascript/axios/2024-12-27-gemini-2.0-flash-thinking-exp) - [attack-surface](javascript/axios/2024-12-27-gemini-2.0-flash-thinking-exp/attack-surface.md), [attack-tree](javascript/axios/2024-12-27-gemini-2.0-flash-thinking-exp/attack-tree.md), [sec-design](javascript/axios/2024-12-27-gemini-2.0-flash-thinking-exp/sec-design.md), [threat-modeling](javascript/axios/2024-12-27-gemini-2.0-flash-thinking-exp/threat-modeling.md)
  - [express](javascript/express) - [github link](https://github.com/expressjs/express)
- [python](python)
  - [flask](python/flask) - [github link](https://github.com/pallets/flask)
    - [2024-12-27-gemini-2.0-flash-thinking-exp](python/flask/2024-12-27-gemini-2.0-flash-thinking-exp) - [attack-surface](python/flask/2024-12-27-gemini-2.0-flash-thinking-exp/attack-surface.md), [attack-tree](python/flask/2024-12-27-gemini-2.0-flash-thinking-exp/attack-tree.md), [sec-design](python/flask/2024-12-27-gemini-2.0-flash-thinking-exp/sec-design.md), [threat-modeling](python/flask/2024-12-27-gemini-2.0-flash-thinking-exp/threat-modeling.md)
  - [requests](python/requests) - [github link](https://github.com/psf/requests)
    - [2024-12-27-gemini-2.0-flash-thinking-exp](python/requests/2024-12-27-gemini-2.0-flash-thinking-exp) - [attack-surface](python/requests/2024-12-27-gemini-2.0-flash-thinking-exp/attack-surface.md), [attack-tree](python/requests/2024-12-27-gemini-2.0-flash-thinking-exp/attack-tree.md), [sec-design](python/requests/2024-12-27-gemini-2.0-flash-thinking-exp/sec-design.md), [threat-modeling](python/requests/2024-12-27-gemini-2.0-flash-thinking-exp/threat-modeling.md)

## Support **sec-docs**  

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
