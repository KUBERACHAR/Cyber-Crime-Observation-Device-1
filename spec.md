## AI-Based Cyber Crime Observation Device

# Project Description: Concept
 - Software-Defined Observation
 The AI-Based Cyber Crime Observation Device is a lightweight, software-based telemetry and threat monitoring engine designed to mimic real-world Security Operations Centers (SOCs).
 It captures granular system events, active processes, and network packets directly from host endpoint devices without requiring expensive dedicated hardware appliances.
 - AI-Driven Threat Detection
 Unlike conventional antivirus solutions relying on static hash signatures, this system employs supervised and unsupervised machine learning algorithms to detect zero-day suspicious behavior.
 It continuously analyzes process execution dynamics, rapid file modifications, and unusual network socket connections in real time.

# Project Description: SOC Paradigm

 - Emulating Enterprise SOC Operations
 Modern enterprise cybersecurity relies on continuous visibility across endpoints and networks. Our observation device brings enterprise SOC capability into an accessible single-laptop setup.
 By capturing endpoint logs, file system mutations, and network packet headers in unified JSON streams, the system establishes complete situational awareness for modern cyber defense.

# Project Description: Core Pillars

- 1. Telemetry Capture
Continuous collection of low-level host metrics (CPU, RAM, running tasks) and active network socket states via cross-platform sensors.
- 2. Machine Intelligence
Feature extraction and classification utilizing Ensemble Decision Trees (Random Forest) and Anomaly Detection (Isolation Forest).
- 3. Real-Time Visibility
Interactive web dashboard providing immediate threat severity scores, process trees, and high-priority threat alerts.

# Problem Statement: Threat Evolution

- Sophisticated Cyber Attacks
Modern malicious software no longer relies solely on static file payloads. Attackers utilize living-off-the-land techniques, fileless malware, and encrypted code to bypass standard security filters.
Traditional endpoint security tools fail to contextualize processes executing malicious commands in rapid sequence.

- Endpoint Blindspots
Small organizations and academic labs lack access to enterprise-grade Security Information and Event Management (SIEM) tools due to prohibitive licensing costs and complex hardware requirements.
This creates significant blindspots where unauthorized data exfiltration goes undetected for extended periods.

# Objectives: Primary Technical Goals

1. Sensor Development
Build on modular Python sensors to continuously track host CPU, memory, active processes, and network socket connections.
2. Machine Learning Engine
Trained Scikit-Learn Random Forest models to evaluate incoming system event streams and accurately classify behaviors as Normal or Suspicious.
3. Real-Time SOC UI
Construct a Streamlit interactive dashboard displaying threat scores, system metrics, active process tables, and alert notifications.

# Objectives: Performance Metrics
- Low Latency Event Processing
Ensure end-to-end event collection, feature extraction, and AI prediction occurs within 500 milliseconds of process initialization or file creation.
Maintain consistent event schema validation using standardized JSON formatting across all sensor payloads.

- High Detection Accuracy
Achieve greater than 90% classification accuracy on anomalous behavior scenarios (e.g., rapid file dumping, unauthorized PowerShell execution).
Minimize false positive rates during standard routine workflows (e.g., browsing, code editing, PDF reading).

# Project Scope: Functional Boundary
 1. In-Scope Capabilities
 - Endpoint resource tracking (CPU %, RAM %, active process list, user sessions).
 - Network connection tracking (Source/Destination IP, Port numbers, TCP states).
 - File system creation and deletion events in targeted directory paths via Watchdog.
 - Supervised AI classification model trained on lightweight event dataset.
 - Human-in-the-loop active response: on a threat alert, the dashboard requests
   user permission and terminates the confirmed process (core system processes
   and the monitor itself are always protected).

 2. Out-of-Scope Elements
 - Kernel-level driver development or Ring-0 deep memory inspection.
 - Fully automated (no-confirmation) response or remote endpoint isolation.
 - Deep packet payload decryption for SSL/TLS encrypted traffic channels.
 - Multi-tenant enterprise cloud database cluster synchronization.
 
# Demonstration Flow Scenario

1. System Start
Sensors launch; baseline activity (Chrome, VS Code) logged as Normal.
2. Attack Trigger
Powershell script starts, spawning rapid file additions in Downloads.
3. AI Evaluation
Feature vector extracted; ML predicts 92% threat probability score.
4. Dashboard Alert
Streamlit UI displays red threat alert with diagnostic metrics.
5. Guided Response
UI lists the flagged process and asks permission; on user confirmation it
terminates the process and records the action in the response log.


* Give me Development Roadmap
* What are the pre-set up that should be done by me
* What should be done by me as a developer to setup this project