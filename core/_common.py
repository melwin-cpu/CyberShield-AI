import os
import sys
import time
import traceback

AI_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(AI_DIR)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

DATASET_DIR = os.path.join(PROJECT_ROOT, "dataset")
MODEL_DIR = os.path.join(PROJECT_ROOT, "models")


def run_jobs(jobs):
    """jobs = [(name, callable)] -> runs each, never stops on error."""
    results = []

    for name, job in jobs:
        print("\n" + "#" * 60)
        print(f"# TRAINING: {name}")
        print("#" * 60)

        started = time.time()

        try:
            job()
            results.append((name, "OK", time.time() - started))
        except Exception as error:
            traceback.print_exc()
            results.append((name, f"FAILED - {error}", time.time() - started))

    print("\n" + "=" * 60)
    print("TRAINING SUMMARY")
    print("=" * 60)

    for name, status, seconds in results:
        print(f"{name:<16}{status}  ({seconds / 60:.1f} min)")

    return results