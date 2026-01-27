import argparse
import json
import os.path
from importlib import reload

from common import auto_detect_task_id_all
from configs import LANGUAGE_NODEJS, LANGUAGE_JAVA
from feeder import get_scan_feeder, reload_scan_feeder, get_scan_feeder_keys
from sage import single_run_for_ts, single_run_for_java

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run a single analysis task for either TypeScript/JavaScript or Java projects.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter  # 自动显示默认值
    )
    parser.add_argument(
        "--json",
        type=str,
        default="feeder/java_demo/org.quartz-scheduler:quartz-jobs:2.4.0_result.json",
        help="Path to the JSON file containing scan feeder data. If provided and exists, it will be loaded to initialize the feeder."
    )
    parser.add_argument(
        "--task_id",
        type=str,
        default="apidoc-core@0.15.0_0",
        help="Unique identifier of the task to analyze (e.g., 'package@version_index' for js or 'group:artifact:version' for java)."
    )
    parser.add_argument(
        "--session_id",
        type=str,
        default="abc",
        help="Session id used to isolate runs/environments on the backend. Usually no need to change."
    )
    parser.add_argument(
        "--remote_ip",
        type=str,
        default="http://127.0.0.1:58080",
        help="VulnSage backend base URL (e.g., http://127.0.0.1:58080)."
    )
    parser.add_argument(
        "--language",
        type=str,
        default="ts",
        choices=[LANGUAGE_NODEJS, LANGUAGE_JAVA],
        help=f"Programming language of the project to analyze. Supported values: '{LANGUAGE_NODEJS}' (for TypeScript/JavaScript) or '{LANGUAGE_JAVA}' (for Java)."
    )
    parser.add_argument(
        "--output",
        type=str,
        default="result.json",
        help="Path to the output file where the analysis result will be saved (in JSON format)."
    )

    args = parser.parse_args()

    # Validate and load JSON if provided
    if args.json:
        if not os.path.exists(args.json):
            raise ValueError(f"File {args.json} not found")
        reload_scan_feeder(args.json)

    # Auto-detect task IDs from feeder
    auto_detect_task_id_all(
        [get_scan_feeder(i) for i in get_scan_feeder_keys()],
        remote_ip=args.remote_ip
    )

    # Run analysis based on language
    if args.language == LANGUAGE_NODEJS:
        r = single_run_for_ts(args.task_id, args.session_id, args.remote_ip)
    elif args.language == LANGUAGE_JAVA:
        r = single_run_for_java(args.task_id, args.session_id, args.remote_ip)
    else:
        raise ValueError(f"Language {args.language} not supported")

    # Save result
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(r[2])
