---
title: RootAI Semantic Parser
emoji: 🛡️
colorFrom: blue
colorTo: gray
sdk: docker
app_port: 7860
pinned: true
license: apache-2.0
---

# 🛡️ RootAI: Semantic Firewall & Reasoning Engine

**Project Status:** Alpha reasoning deployment for OpenAI-Codex Challenge 2026

RootAI is a polyglot technical engine designed to transition AI from simple prediction to **deterministic comprehension** of complex codebases. By transforming raw source code into structured semantic graphs, it provides the "eyes" for Large Language Models to reason over logic, flow, and intent.

## 🧩 The Jinn Guard Architecture

This parser serves as the primary logic layer for the **Jinn Guard**—a semantic firewall for autonomous agents. Its function is mapping inter-agent intent to security constraints to prevent AI-to-AI collusion.

---

## 🚀 Live Demo (Hugging Face)

Access the **Sovereign Command Deck**:  
https://huggingface.co/spaces/alpha-reasoning/rootai-semantic-parser

## 🛠️ Logic & Analysis

- **Polyglot Parsing:** Native support for Python, JavaScript, Go, Java, and C#
- **Deterministic Reasoning:** Logic validation via `sovereign-rules-v1.json`
- **Taint Analysis:** Multi-hop data flow tracing for vulnerability discovery

---

## 📦 Local Install

### Runtime Install

```bash
python3 -m pip install .
```

### Development Install

```bash
python3 -m pip install -r requirements-dev.txt
```

---

## 🧪 CLI Usage

### Help

```bash
semantic-parser --help
python3 -m rootai_semantic_parser --help
```

### Example Scan

```bash
semantic-parser --profile human-only --min-score 6.5 /path/to/repo scan --format bounty-json
```

### Custom Finding Profile

```bash
semantic-parser --profile-file ./human-only.json /path/to/repo bounty-report
```

---

## 🐳 Docker

### Build

```bash
docker build -t rootai-semantic-parser .
```

### Run

```bash
docker run --rm -v "$PWD:/work" rootai-semantic-parser /work scan --format text
```

### Run with Custom Profile

```bash
docker run --rm -v "$PWD:/work" rootai-semantic-parser \
  --profile-file /work/human-only.json \
  /work bounty-report
```

---

## 🚀 Deployment

Once you save the file, upload to Hugging Face Spaces:

```bash
hf upload alpha-reasoning/rootai-semantic-parser . . --repo-type space
```

---
CMD ["python3", "-m", "streamlit", "run", "app.py", "--server.port", "7860", "--server.address", "0.0.0.0"]

**alpha-reasoning lab | Loyal Rameriz LLC | 2026-04-17**
