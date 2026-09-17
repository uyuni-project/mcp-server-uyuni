import pytest
import re
import statistics

def pytest_configure(config):
    """
    Hook to initialize a list for storing stats on the pytest config object.
    This makes it available across the entire test session.
    """
    config.goose_stats = []

@pytest.fixture(scope="session")
def goose_stats_collector(request):
    """
    A fixture that provides access to the session-wide stats collector.
    """
    return request.config.goose_stats

def pytest_sessionfinish(session, exitstatus):
    """
    This hook is called after the entire test session finishes.
    It will parse all collected stats and print an aggregated summary.
    """
    print("\n--- Goose Stats Summary ---")
    all_stats = session.config.goose_stats
    if not all_stats:
        print("No goose stats were collected.")
        return

    first_token_times = []
    tokens_per_sec_rates = []
    total_output_tokens = 0

    for test_id, stat_block in all_stats:
        print(f"  - Test: {test_id}")
        for line in stat_block.splitlines():
            if "Time to first token:" in line:
                match = re.search(r"(\d+\.\d+)s", line)
                if match:
                    first_token_times.append(float(match.group(1)))
            if "Tokens/sec:" in line:
                match = re.search(r"(\d+\.\d+)", line)
                if match:
                    tokens_per_sec_rates.append(float(match.group(1)))
            if "Output tokens:" in line:
                match = re.search(r"(\d+)", line)
                if match:
                    total_output_tokens += int(match.group(1))

    print(f"Total Goose Runs: {len(all_stats)}")
    print(f"Total Output Tokens: {total_output_tokens}")
    if first_token_times:
        print(f"Avg. Time to First Token: {statistics.mean(first_token_times):.2f}s (min: {min(first_token_times):.2f}s, max: {max(first_token_times):.2f}s)")
    if tokens_per_sec_rates:
        print(f"Avg. Tokens/Sec: {statistics.mean(tokens_per_sec_rates):.2f} (min: {min(tokens_per_sec_rates):.2f}, max: {max(tokens_per_sec_rates):.2f})")
    print("--------------------------")