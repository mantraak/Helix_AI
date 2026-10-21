# Helix AI — Self-Healing Intrusion Detection System

Helix AI is a security project focused on intrusion detection and LLM-assisted analysis, using **TinyLLaMA** as part of its approach to understanding security events and supporting a self-healing workflow.

The repository is organized into a `backend/` and a `frontend/` application.

> **Note:** Automated remediation should be reviewed and tested carefully before being enabled in a real environment. Treat model-generated explanations or recommendations as advisory unless they are validated by explicit security policies.

## Overview

Traditional intrusion detection systems can identify suspicious activity but may still require an operator to interpret alerts and decide what to do next. Helix AI explores combining detection with an LLM-assisted analysis and response workflow.

The intended workflow is:

1. **Detect** — identify suspicious events using the project's detection pipeline.
2. **Analyze** — use TinyLLaMA-assisted reasoning to help interpret relevant event information.
3. **Respond** — connect the analysis to the project's configured response or recovery workflow.
4. **Review** — inspect results and logs to evaluate the outcome and improve future handling.

The exact detectors, response actions, and supported event types depend on the current implementation in this repository.

## Repository Structure

```text
Helix_AI/
├── backend/     # Backend services and detection/analysis logic
├── frontend/    # User interface
└── README.md
```

## Key Goals

- Detect and surface potentially suspicious activity.
- Use TinyLLaMA to support security-event interpretation.
- Provide a workflow for connecting detections with response or recovery actions.
- Separate backend processing from the frontend interface.
- Make investigation and testing easier to follow.

## Requirements

Install the runtimes and tools required by the backend and frontend. Check the manifests and configuration files in each directory before installing dependencies. Depending on the implementation, you may also need a local or hosted TinyLLaMA runtime and model, plus any configured data stores or security tools.

## Setup and Run

### 1. Clone the repository

```bash
git clone https://github.com/mantraak/Helix_AI.git
cd Helix_AI
```

### 2. Configure the backend

Open the `backend/` directory and review its dependency manifest and configuration files. Install the dependencies specified by the project and configure any required environment variables or model/runtime settings. Do not commit API keys, passwords, tokens, or other secrets.

### 3. Configure the frontend

Open the `frontend/` directory and review its dependency manifest and configuration files. Install its dependencies and set the backend API URL or other required frontend configuration values.

### 4. Start the applications

Start the backend and frontend using the development commands defined by their respective project manifests or setup scripts. Keep each process running in its own terminal if the project requires the services to run separately.

> Exact install and start commands are intentionally not specified here because the current directory manifests and scripts could not be verified from the public repository view. Use the commands defined in the checked-out source rather than assuming a particular framework or package manager.

## Configuration and Security

- Keep credentials and environment-specific configuration out of source control.
- Use example configuration files for documentation; never publish real secrets.
- Test detection and recovery actions in an isolated environment before connecting them to production systems.
- Require explicit policy checks and appropriate authorization before taking actions that can disable services, alter system settings, or block traffic.
- Record actions and outcomes so that false positives and failed recovery attempts can be investigated.
- Do not rely on LLM output alone to make high-impact security decisions.

## Testing

Test the project in a controlled environment with benign examples and carefully chosen security-event samples. Validate detection results, inspect the LLM-assisted analysis, and confirm that any response action behaves as intended. Measure false positives and false negatives before using the system operationally.

## Limitations

- Detection quality depends on the implemented detector, its input data, and its configuration.
- TinyLLaMA-generated analysis can be incomplete or incorrect and should be independently validated.
- Automatic response can cause unintended disruption if rules are too broad; apply least privilege and safe defaults.
- Supported operating systems, event sources, and deployment modes should be confirmed from the implementation before deployment.

## Contributing

1. Create a branch for your change.
2. Keep changes focused and document any new configuration requirements.
3. Test backend and frontend changes where applicable.
4. Open a pull request describing the change, how it was tested, and any security implications.

## Upstream Project

This repository was created from the project published at [JOHN-DANIELISSAC/Helix-Ai](https://github.com/JOHN-DANIELISSAC/Helix-Ai). Refer to the upstream repository for its original history and project context. Check the upstream license and preserve any required notices before redistributing or modifying the project.

## License

No license terms are stated here. Check the repository and upstream project for a `LICENSE` file before reusing or redistributing the code.
