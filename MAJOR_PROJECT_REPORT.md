# VulnShield: AI-Powered Repository Security Intelligence Platform

## 1. Executive Summary

VulnShield is an advanced repository security intelligence system designed to help developers and security teams identify vulnerable dependencies, understand repository context, generate evidence-based remediation advice, and evaluate the safety of proposed fixes. The project combines dependency vulnerability scanning, repository profiling, semantic retrieval, knowledge-graph reasoning, and AI-assisted remediation ranking into a unified platform.

The core value of the system is not simply to detect known vulnerabilities, but to answer more useful questions: Which vulnerabilities matter in this repository? Why do they matter in this codebase? What is the safest fix? How confident are we in the recommendation? What is the overall security posture of the project?

This project is particularly relevant in modern software engineering, where applications depend on dozens or hundreds of packages across multiple ecosystems. A static CVE list is often not enough because a vulnerability may be severe in one project and low priority in another depending on usage patterns, package manager behavior, compatibility constraints, and repository architecture.

VulnShield addresses this gap by combining deterministic data sources, such as OSV, NVD, GitHub advisories, and CISA KEV, with repository-aware analysis and AI-supported reasoning. The final output is a practical decision-support tool rather than a fully autonomous security system.

---

## 2. Introduction

In the current software ecosystem, dependency vulnerabilities are a major source of software risk. The increasing size and complexity of modern repositories, as well as the speed of package updates, make it difficult for developers to know which vulnerabilities require immediate action and which ones should be deprioritized.

Many existing security tools focus on one layer only:

- package scanning,
- vulnerability database lookup,
- static analysis,
- or general AI-based coding assistance.

These tools often fail to connect security findings to repository context. For example, a project may use a vulnerable dependency in a development-only package, or a vulnerability may affect a library that is not actually reachable in the running application. In those cases, a generic scanner produces noise rather than actionable intelligence.

The motivation behind this project is to create a more useful system that combines:

- vulnerability intelligence,
- repository understanding,
- graph-based context modeling,
- semantic retrieval of relevant files,
- AI-assisted recommendation generation,
- and validation of remediation options.

The platform is designed to support developers, security analysts, and project stakeholders in making informed security decisions.

---

## 3. Problem Statement

The major challenge in modern software security is not merely discovering package vulnerabilities, but understanding their relevance and deciding the best remediation path.

Some of the core problems addressed by this project are:

1. Vulnerability databases report many package issues, but do not explain which are important for a specific repository.
2. Security teams need contextual understanding beyond CVE IDs and numeric severity scores.
3. Developers often receive remediation suggestions without validation of compatibility, dependency risk, or real availability of the proposed version.
4. Upgrading a vulnerable package may create broader compatibility issues, transitive conflicts, or breakage.
5. Security tools rarely integrate repository architecture, code structure, and threat intelligence in a single decision-making workflow.

The project addresses these problems through a unified, repository-aware security intelligence approach.

---

## 4. Aim and Objectives

### Aim
To design and implement an intelligent vulnerability detection and remediation system that analyzes public GitHub repositories, identifies vulnerable dependencies, understands repository context, and recommends justified remediation actions.

### Objectives

1. To scan GitHub repositories for vulnerable dependencies across multiple ecosystems.
2. To parse dependency manifests such as package.json, pom.xml, and Python requirements files.
3. To integrate multiple vulnerability sources such as OSV, NVD, GitHub Advisory, and CISA KEV.
4. To profile repository architecture and usage context.
5. To build a repository knowledge graph that links dependencies, files, modules, and vulnerabilities.
6. To retrieve relevant repository evidence using semantic and lexical retrieval.
7. To generate context-aware remediation recommendations.
8. To validate remediation candidates and rank them based on safety and compatibility.
9. To compute a repository-level security intelligence score.
10. To provide a usable web dashboard, CLI, and REST API for interaction.

---

## 5. Scope of the Project

### In Scope

- Public GitHub repositories
- npm, Maven, and Python dependency analysis
- Known vulnerability detection and enrichment
- Repository profiling using files, manifests, and README content
- Knowledge-graph-based contextualization
- Semantic retrieval and evidence extraction
- AI-assisted remediation reasoning
- Threat prioritization using KEV signals
- Final output in the form of explanatory reports and dashboard views

### Out of Scope

- Automatically patching code or opening pull requests
- Private repository or enterprise access control workflows
- Proof of runtime exploitability in specific deployments
- Full dependency analysis across every package ecosystem and lockfile format
- Guaranteeing that all LLM-generated recommendations are always correct

This distinction is important because the project is designed to support secure decision-making, not replace human review or testing.

---

## 6. Motivation and Significance

The relevance of this project lies in real-world software engineering practices. The average modern application includes numerous open-source dependencies, and each of them may carry security risk. Tracking these risks manually is expensive and unreliable.

This system helps answer critical questions such as:

- Which dependency vulnerabilities are relevant to this project?
- Are the affected packages used in production or only in development?
- What is the safest upgrade path?
- Are there known exploited vulnerabilities in this dependency set?
- Is the proposed fix compatible with the project’s ecosystem and architecture?

By combining data from dependency scanners, security intelligence feeds, and repository context, the project provides actionable security insight instead of a flat list of CVEs.

---

## 7. Literature Review and Background

### 7.1 Dependency Vulnerability Scanning
Traditional dependency scanners examine manifest files and check dependencies against known vulnerabilities. Common sources include OSV, NVD, GitHub Advisory, and language-specific advisories. These databases are useful but often limited by context and scope.

### 7.2 Knowledge Graphs for Software Analysis
Knowledge graphs are increasingly used in software analysis because they can model relationships among packages, modules, files, vulnerabilities, fixes, and code references. In the context of this project, the repository knowledge graph serves as a map of how dependencies and vulnerabilities relate to the project.

### 7.3 Retrieval-Augmented Analysis
Retrieval-based systems are effective when relevant files, configuration snippets, or code patterns are required to contextualize a finding. In security tools, retrieval helps ground the explanation in the specific repository state instead of relying solely on generic vulnerability summaries.

### 7.4 AI-Assisted Security Decision Support
Large language models can make explanations more understandable and can support reasoning over structured data. However, LLMs can hallucinate, especially if the context is incomplete or poorly grounded. For that reason, this project uses AI as an augmentation layer rather than the sole authority.

### 7.5 Why This Project Is Different
This project integrates the above ideas into a single workflow: scan dependencies, understand repository structure, retrieve evidence, validate candidate fixes, and present a reasoned output. It is built to be practical, explainable, and resilient.

---

## 8. System Architecture

The system follows a modular architecture with several major components:

### 8.1 Frontend Layer
- Next.js web application
- User interaction for submitting repository URLs
- Visualization of security summaries and analysis results
- Views for scan results, RSIS score, remediation suggestions, and similar repository references

### 8.2 API Layer
- Express REST API
- Endpoints for health checks, scanning, full analysis, metrics, and stored results
- Handles request validation and backend orchestration

### 8.3 Core Engine
The core engine contains the logic for:

- repository scanning,
- manifest parsing,
- dependency matching,
- vulnerability enrichment,
- repository understanding,
- semantic chunking,
- retrieval,
- graph construction,
- remediation ranking,
- and RSIS computation.

### 8.4 Data Layer
- PostgreSQL database
- Prisma ORM
- Storage for scans, dependencies, vulnerabilities, and intelligence results
- Vector support for semantic retrieval

### 8.5 External Intelligent Services
- OSV
- NVD
- GitHub Advisory
- CISA KEV
- Groq and Gemini APIs (when available)

---

## 9. Detailed Methodology

### 9.1 Repository Input and Manifest Parsing
The system accepts a public repository URL or repository identifier. It fetches project metadata and inspects all relevant dependency manifests. Dependencies are normalized into a common format across ecosystems.

Supported dependency parsing includes:
- npm manifests
- Maven project descriptors
- Python requirement files

The parser extracts names, versions, ecosystems, dependency type, and manifest location.

### 9.2 Vulnerability Matching
The discovered dependencies are matched against vulnerability databases. The project emphasizes data sources that provide both breadth and context. OSV serves as the primary match engine, while NVD and advisories provide supporting enrichment.

This stage produces:
- vulnerable package entries,
- affected versions,
- severity labels,
- CVSS data,
- fix information,
- advisory reference links,
- and KEV indicators.

### 9.3 Repository Understanding
Repository understanding is performed using file structure, manifests, configuration files, and documentation. The system identifies characteristics such as:

- primary programming language,
- framework,
- database technology,
- ORM,
- deployment model,
- auth method,
- CI/CD patterns,
- testing tools,
- package manager,
- and project type.

This information is important because it improves the relevance of recommendations and helps explain why the repository is vulnerable or how risky a fix might be.

### 9.4 Source Chunking and Retrieval
The source code is broken into manageable chunks based on logical structure, especially in JavaScript, TypeScript, and Python. The retrieval layer indexes these chunks and searches for the most relevant files and evidence based on both semantics and keyword relevance.

The system can use:
- semantic vectors for context-aware retrieval,
- lexical matching for exact identifiers,
- hybrid retrieval to combine dense and sparse signals.

This allows the system to connect security issues to the code locations that matter most.

### 9.5 Repository Knowledge Graph
The repository knowledge graph models relationships between:

- repository,
- folders,
- files,
- modules,
- dependencies,
- vulnerabilities,
- advisory entries,
- and fix nodes.

This graph adds structure to the analysis and improves explainability. A vulnerability is not just a database record; it is connected to the project context and to the files that matter.

### 9.6 Remediation Candidate Generation
The system produces candidate remediation options by identifying secure or updated package versions. These are then validated against package registries and other sources to determine whether they exist and whether they appear to be safe.

Candidate evaluation includes:
- version existence,
- vulnerability status,
- release type,
- compatibility risk,
- and repository-specific impact.

### 9.7 Ranking and RSIS Score
Each candidate is ranked according to a multi-feature score that includes:
- security improvement,
- compatibility risk,
- validation confidence,
- evidence strength,
- and repository context.

The platform also computes a Repository Security Intelligence Score (RSIS), a repository-level composite measure that summarizes current risk and remediation posture.

---

## 10. Core Modules and Features

### 10.1 VulnerabilityScanner
This module is responsible for the dependency scan and vulnerability matching workflow. It collects manifest data, normalizes dependency objects, and checks them against vulnerability databases.

### 10.2 GitHubClient
This module interacts with public GitHub metadata and repository content to collect tree information, manifest files, and repository-level insights.

### 10.3 Parsers
The project includes separate parsing logic for:
- npm packages,
- Maven dependencies,
- Python packages and requirements.

This modularity improves maintainability and allows the system to scale to additional ecosystems in the future.

### 10.4 RepoUnderstander
This module generates the repository profile. It infers framework usage, database type, deployment style, CI/CD layout, and testing setup using deterministic analysis of files and configuration patterns.

### 10.5 KnowledgeGraphBuilder
This module builds and traverses the repository graph to connect package dependencies with files, modules, and vulnerabilities.

### 10.6 ContextRetriever
This module retrieves relevant repository evidence using semantic and lexical search. It helps the system ground explanations in actual repository context.

### 10.7 Reasoner and Validator
These modules generate remediation reasoning and validate whether a recommended package version is plausible, safe, and aligned with project constraints.

### 10.8 CandidateRanker
This module ranks remediation options according to expected security gain, compatibility, and operational fit.

### 10.9 RSISScorer
This module creates a summary score that captures repository security posture using multiple factors rather than severity alone.

---

## 11. Evaluation Strategy

The project should be evaluated using both qualitative and quantitative methods.

### 11.1 Functional Evaluation
The system can be tested by scanning known vulnerable and non-vulnerable repositories and checking whether:
- vulnerabilities are correctly detected,
- the parser identifies dependencies correctly,
- the ranking is relevant,
- the repository profile is accurate enough,
- and the remediation recommendations are plausible.

### 11.2 Precision and Recall
The vulnerability detection pipeline can be evaluated using standard metrics such as:
- precision,
- recall,
- F1-score,
- top-k recommendation success,
- and success rate of remediation validation.

### 11.3 Retrieval Metrics
Semantic retrieval can be evaluated using metrics such as:
- MRR,
- NDCG,
- hit rate at k,
- and retrieval similarity quality.

### 11.4 Ranking Evaluation
Candidate ranking quality can be evaluated by measuring whether the top recommendations correspond to safer or more appropriate fixes than lower-ranked options.

### 11.5 Repository Score Validation
The RSIS score should be interpreted as a decision-support metric, not a definitive ground truth. It can be compared with expert judgment and vulnerability density across public repositories.

---

## 12. Tools and Technologies Used

| Layer | Technologies |
| --- | --- |
| Runtime | Node.js, TypeScript |
| Monorepo | pnpm workspace |
| API | Express |
| Frontend | Next.js, React |
| Database | PostgreSQL, Prisma |
| Vector Storage | pgvector |
| Vulnerability Data | OSV, NVD, GitHub Advisory, CISA KEV |
| AI Providers | Groq, Gemini |
| Validation | SemVer logic and registry-aware checks |

These technologies were chosen to balance functionality, scalability, interpretability, and project feasibility.

---

## 13. System Benefits

The project provides several important benefits:

1. Faster vulnerability triage for repositories.
2. Better understanding of repository context behind a finding.
3. Explainable remediation suggestions.
4. Reduced noise from irrelevant or low-impact alerts.
5. More actionable security reporting.
6. A structured interface for both developers and evaluators.

This makes the project valuable not only academically but also operationally.

---

## 14. Limitations and Risk Areas

Although the system is useful, it has some limitations:

- It does not prove exploitability in runtime environments.
- It relies on public repository state and can miss private code details.
- Some AI-generated recommendations may require human validation.
- External APIs may rate-limit or fail.
- The repository profile is heuristic and may be imperfect.
- Compatibility assumptions may differ across real-world deployment environments.

These are important to acknowledge in a major project report because they demonstrate scientific maturity and realism.

---

## 15. Ethical and Practical Considerations

Security tools can have a high impact on software teams. It is therefore important to use them responsibly.

Key considerations include:

- not overclaiming an exploit,
- not treating LLM output as fact without validation,
- not ignoring compatibility risk,
- and clearly separating security evidence from speculative reasoning.

This project follows an evidence-first approach in which the data sources, repository evidence, and validation steps remain transparent.

---

## 16. Future Scope

The project has strong future potential. Possible extensions include:

1. Support for more ecosystems and lockfiles.
2. Real-time dependency monitoring for repositories.
3. More advanced graph analysis for transitive vulnerability chains.
4. Deeper code-level reachability analysis.
5. CI/CD integration for automated vulnerability policy checks.
6. Improved model tuning for remediation ranking.
7. Better enterprise support for private repositories and internal policies.
8. Visualization of exploit risk and remediation timelines.

The current version provides a strong foundation for these enhancements.

---

## 17. Conclusion

VulnShield represents a practical and academically relevant solution to the problem of repository-aware vulnerability analysis. Instead of simply listing vulnerabilities, the system attempts to explain, prioritize, and validate remediation decisions within the context of a real repository.

The project successfully combines dependency scanning, repository intelligence, retrieval, knowledge graphs, AI augmentation, and security scoring into a single system. It is especially promising because it balances technical innovation with practical usability and transparency.

This makes it a strong final-year major project because it addresses both research and engineering problem areas while producing a complete and useful software system.

---

## 18. Questions That Can Be Asked in Viva / Presentation

Below is a set of likely examiner questions and strong sample answers.

### Q1. What is the main problem your project solves?
A: The main problem is that many vulnerability scanners identify vulnerable dependencies but do not explain whether those vulnerabilities matter in a specific repository, how risky the fix is, or which remediation path is safest. VulnShield addresses this by combining dependency scanning, repository context, evidence retrieval, and ranked remediation analysis.

### Q2. Why is this project important in today’s software industry?
A: Modern software depends heavily on third-party packages. As the dependency graph grows, manual review becomes impractical. This project helps engineering teams prioritize risk, understand repo context, and make better remediation decisions.

### Q3. What is the difference between scanning and actual vulnerability analysis?
A: Scanning tells whether a package version is known to be vulnerable. Analysis adds repository context, impact estimation, evidence quality, compatibility risk, and remediation validity. This is more actionable and realistic.

### Q4. What are the major technologies used?
A: The project uses TypeScript, Node.js, Next.js, Express, PostgreSQL, Prisma, and external security data providers such as OSV and NVD. It also uses AI providers for contextual reasoning and a deterministic fallback when those providers are unavailable.

### Q5. Why did you choose a modular architecture?
A: Modular design makes the system maintainable, testable, and extensible. Each component like parsing, retrieval, graph building, and ranking can be improved independently without affecting the whole system.

### Q6. What is the role of the repository knowledge graph?
A: The graph connects repository files, modules, dependencies, and vulnerabilities. This makes the analysis explainable and helps us trace how a package issue relates to the project structure.

### Q7. Why is AI used only as a support layer instead of as the main decision-maker?
A: AI can generate useful explanations and recommendations, but it may hallucinate or overgeneralize. In this project, AI is used with grounded evidence and validation pipelines to reduce risk.

### Q8. How do you handle missing or failed API services?
A: The project uses a fallback strategy. If Groq or Gemini is unavailable, the system falls back to heuristic reasoning and deterministic evidence-based output instead of failing completely.

### Q9. What is RSIS and why is it useful?
A: RSIS is a Repository Security Intelligence Score. It summarizes the repository’s overall security posture using factors such as vulnerability severity, evidence quality, validation, maintainability, and compatibility. It helps move beyond raw CVE counts.

### Q10. What are the limitations of your system?
A: It does not prove runtime exploitability, it depends on public repository state, and it cannot fully replace developer testing and review. It is designed to support decision-making, not automate final security validation.

### Q11. How do you validate remediation candidates?
A: Candidate fixes are checked for version availability, compatibility patterns, and known vulnerability safety. This reduces the risk of suggesting an invalid or harmful upgrade.

### Q12. How does your system understand the repository context?
A: It uses repository metadata, file/folder structure, dependency manifests, README content, configuration files, and code chunking to infer language, framework, architecture, and usage context.

### Q13. Why is repository-aware analysis better than a dependency-only scan?
A: A dependency-only scan may flag issues without knowing whether they are used in production or if the project is on an incompatible stack. Repo-aware analysis improves prioritization and real-world usefulness.

### Q14. What is the significance of the knowledge graph in threat prioritization?
A: It helps connect vulnerabilities to affected areas of the repository and provide a more structured view of impact, making it easier to prioritize the most relevant threats.

### Q15. Is the project fully autonomous?
A: No. It supports decisions, but final validation, deployment safety checks, and patching decisions still require human review.

### Q16. How does the project handle multi-ecosystem dependencies?
A: The project uses ecosystem-specific parsers that normalize results into a common internal structure, allowing vulnerability data to be processed consistently across npm, Maven, and Python dependencies.

### Q17. What was the biggest technical challenge during development?
A: One of the biggest challenges was combining deterministic evidence with AI-assisted reasoning while maintaining explainability and reliability. This required careful data modeling and fallback design.

### Q18. What would you improve if you had more time?
A: I would expand ecosystem support, improve runtime reachability analysis, add stronger evaluation pipelines, and integrate CI/CD or repo monitoring workflows.

### Q19. Why is explainability important in security tools?
A: Security decisions often affect product release, patching policy, and engineering priorities. If a system cannot explain its reasoning, users cannot trust or validate it.

### Q20. What is your final-year project contribution?
A: My contribution is the design and implementation of an integrated repository-aware vulnerability intelligence system that combines scanning, retrieval, graph-based context modeling, AI-assisted reasoning, and remediation ranking into a single practical platform.

---

## 19. Viva-Ready Summary Statement

VulnShield is a repository-aware vulnerability intelligence platform that goes beyond dependency scanning by combining security intelligence, repository context, evidence retrieval, and remediation validation. It helps developers answer not only whether a package is vulnerable, but also whether it matters in their project and what the safest remediation path is.

---

## 20. Final Note

This project is suitable as a major project because it sits at the intersection of software engineering, security analysis, data modeling, and applied AI. It is practically useful, technically rich, and academically meaningful.
