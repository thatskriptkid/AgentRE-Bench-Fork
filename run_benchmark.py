#!/usr/bin/env python3
"""
AgentRE-Bench — CLI entry point

API keys are loaded from .env in the project root. Create one with:
    ANTHROPIC_API_KEY=sk-ant-...
    OPENAI_API_KEY=sk-...
    GOOGLE_API_KEY=AI...
    DEEPSEEK_API_KEY=sk-...
    DASHSCOPE_API_KEY=sk-...   # Alibaba Qwen

Then just pick a provider/model:
    python run_benchmark.py --all --provider anthropic --model claude-opus-4-6
    python run_benchmark.py --all --provider openai --model gpt-4o
    python run_benchmark.py --all --provider gemini --model gemini-2.0-flash
    python run_benchmark.py --all --provider deepseek --model deepseek-chat
    python run_benchmark.py --all --provider qwen --model qwen3-coder-plus
    python run_benchmark.py --task level1_TCPServer --model claude-opus-4-6
    python run_benchmark.py --task level1_TCPServer --model claude-opus-4-6 -v
"""

import argparse
import logging
import sys
from pathlib import Path

from harness.config import BenchmarkConfig
from harness.runner import run_benchmark


def main():
    parser = argparse.ArgumentParser(
        description="AgentRE-Bench: Evaluate LLM agents on reverse engineering tasks",
        epilog="API keys are read from .env file in the project root (or from environment variables).",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--all",
        action="store_true",
        help="Run all tasks (13 for ELF, 12 for PE)",
    )
    group.add_argument(
        "--task",
        type=str,
        help="Run a single task by ID (e.g. level1_TCPServer)",
    )

    parser.add_argument(
        "--provider",
        type=str,
        default="anthropic",
        choices=["anthropic", "openai", "gemini", "deepseek", "qwen"],
        help="LLM provider (default: anthropic)",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Model name (default: provider-specific default)",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default="",
        help="API key override (normally loaded from .env or environment)",
    )
    parser.add_argument(
        "--report",
        type=str,
        default=None,
        help="Custom results directory path",
    )
    parser.add_argument(
        "--max-tool-calls",
        type=int,
        default=25,
        help="Max tool calls per task (default: 25)",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=4096,
        help="Max tokens per LLM response (default: 4096)",
    )
    parser.add_argument(
        "--platform",
        type=str,
        default="elf",
        choices=["elf", "pe"],
        help="Binary platform: elf (Linux ELF) or pe (Windows PE). Default: elf.",
    )
    parser.add_argument(
        "--no-docker",
        action="store_true",
        help="Run tools via subprocess instead of Docker",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show agent reasoning, tool calls, and outputs in real time",
    )

    args = parser.parse_args()

    # Logging is for errors only — all user-facing output goes through print()
    logging.basicConfig(level=logging.WARNING, format="[%(levelname)s] %(message)s")

    # Determine default model per provider
    model_defaults = {
        "anthropic": "claude-opus-4-6",
        "openai": "gpt-4o",
        "gemini": "gemini-2.0-flash",
        "deepseek": "deepseek-chat",
        "qwen": "qwen3-coder-plus",
    }
    model = args.model or model_defaults.get(args.provider, "claude-opus-4-6")

    project_root = Path(__file__).parent.resolve()
    platform = args.platform

    if platform == "pe":
        workspace_dir = project_root / "binaries_pe"
        ground_truths_dir = project_root / "ground_truths_pe"
    else:
        workspace_dir = project_root / "binaries"
        ground_truths_dir = project_root / "ground_truths"

    config = BenchmarkConfig(
        project_root=project_root,
        workspace_dir=workspace_dir,
        ground_truths_dir=ground_truths_dir,
        model=model,
        provider=args.provider,
        api_key=args.api_key,
        max_tool_calls=args.max_tool_calls,
        max_tokens=args.max_tokens,
        use_docker=not args.no_docker,
        results_dir=Path(args.report) if args.report else None,
        verbose=args.verbose,
        platform=platform,
    )

    # Validate
    if not config.workspace_dir.exists():
        hint = (
            "Create binaries_pe/ and add PE samples, and tasks_pe.json + ground_truths_pe/."
            if platform == "pe"
            else "Run ./build_binaries.sh first to compile the samples."
        )
        print(
            f"Error: workspace not found at {config.workspace_dir}\n{hint}",
            file=sys.stderr,
        )
        sys.exit(1)

    if not config.ground_truths_dir.exists():
        print(
            f"Error: ground truths directory not found at {config.ground_truths_dir}",
            file=sys.stderr,
        )
        sys.exit(1)

    task_filter = args.task if args.task else None

    try:
        aggregate, task_metrics, score_results = run_benchmark(config, task_filter)
    except Exception as e:
        logging.getLogger(__name__).error("Benchmark failed: %s", e, exc_info=True)
        sys.exit(1)

    print(f"\nTotal score: {aggregate.total_score:.4f}")
    print(f"Tasks completed: {aggregate.tasks_with_answer}/{aggregate.tasks_run}")
    print(f"Total wall time: {aggregate.total_wall_time:.1f}s")
    print(f"Total tokens: {aggregate.total_tokens}")


if __name__ == "__main__":
    main()
