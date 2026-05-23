"""
Benchmark command - measures speed and latency for any task.
"""

import codecs
import csv
import json
import random
import re
import socket
import statistics
import threading
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed

from mt import config_from_args, TranslateConfig, TimingInfo
from mt.tasks.base import Task


# =============================================================================
# Data structures
# =============================================================================

@dataclass
class BenchmarkResult:
    idx: int
    input_text: str
    duration: float
    success: bool
    output: Optional[str] = None
    error: Optional[str] = None
    timed_out: bool = False
    completed_at: float = 0.0
    pending_time: float = 0.0
    timing: Optional[TimingInfo] = None


# =============================================================================
# Data sources
# =============================================================================

def download_war_and_peace() -> str:
    """Download War and Peace from Gutenberg."""
    url = "https://www.gutenberg.org/files/2600/2600-0.txt"
    print(f"Downloading War and Peace from {url}...")
    with urllib.request.urlopen(url, timeout=30) as response:
        text = response.read().decode('utf-8')
    print(f"Downloaded {len(text)} characters")
    return text


def split_into_chunks(text: str, chunk_length: int) -> List[str]:
    """Split text into chunks of approximate length."""
    text = text.strip()
    chunks = []
    words = text.split()
    current_chunk = []
    current_length = 0

    for word in words:
        word_length = len(word) + 1
        if current_length + word_length > chunk_length and current_chunk:
            chunks.append(' '.join(current_chunk))
            current_chunk = [word]
            current_length = word_length
        else:
            current_chunk.append(word)
            current_length += word_length

    if current_chunk:
        chunks.append(' '.join(current_chunk))

    return chunks


def parse_log_file(logfile: str) -> List[tuple]:
    """Parse log file and extract (target_lang, texts) tuples."""
    queries = []
    with open(logfile, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            match = re.search(r'<HTTP_REQUEST[^>]*>(.*?)</HTTP_REQUEST>', line)
            if not match:
                continue

            payload_escaped = match.group(1)
            try:
                payload_bytes = codecs.decode(payload_escaped, 'unicode_escape')
                if isinstance(payload_bytes, str):
                    payload_bytes = payload_bytes.encode('latin1')
                payload_json_str = payload_bytes.decode('utf-8')
                data = json.loads(payload_json_str)
            except (json.JSONDecodeError, UnicodeDecodeError, UnicodeEncodeError):
                continue

            if 'messages' not in data:
                continue

            user_content = None
            for msg in data['messages']:
                if msg.get('role') == 'user':
                    user_content = msg.get('content', '')
                    break

            if not user_content:
                continue

            try:
                user_data = json.loads(user_content)
            except json.JSONDecodeError:
                continue

            target_lang = user_data.get('target_lang', 'Unknown')
            texts = [item.get('text', '') for item in user_data.get('texts', [])]

            if texts:
                queries.append((target_lang, texts))

    return queries


# =============================================================================
# Timing statistics
# =============================================================================

def calculate_timing_stats(results: List[BenchmarkResult]) -> Optional[dict]:
    """Calculate timing statistics from results with timing info."""
    results_with_timing = [r for r in results if r.timing]
    
    if not results_with_timing:
        return None
    
    worker_overheads = []
    proxy_overheads = []
    client_overheads = []
    network_overheads = []

    for r in results_with_timing:
        client_oh, proxy_oh, worker_oh = r.timing.overheads()
        
        if worker_oh > 0:
            worker_overheads.append(worker_oh)
        if proxy_oh > 0:
            proxy_overheads.append(proxy_oh)
        if client_oh > 0:
            client_overheads.append(client_oh)
        
        cd = r.timing.client_duration()
        if cd is not None and r.duration > 0:
            net_oh = r.duration - cd
            if net_oh > 0:
                network_overheads.append(net_oh)
    
    if not any([worker_overheads, proxy_overheads, client_overheads, network_overheads]):
        return None
    
    return {
        'count': len(results_with_timing),
        'worker_overheads': worker_overheads,
        'proxy_overheads': proxy_overheads,
        'client_overheads': client_overheads,
        'network_overheads': network_overheads
    }


def print_timing_breakdown(timing_stats: dict, prefix: str = ""):
    """Print timing breakdown statistics."""
    count = timing_stats['count']
    print(f"{prefix}Timing Breakdown ({count} requests with timing headers):")

    for name, key in [("Network overhead", 'network_overheads'), 
                      ("Worker duration", 'worker_overheads'),
                      ("Proxy overhead", 'proxy_overheads'), 
                      ("Client overhead", 'client_overheads')]:
        vals = timing_stats[key]
        if vals:
            p90_idx = int(len(vals) * 0.90)
            print(f"{prefix}  {name}: avg: {statistics.mean(vals):.3f}s | "
                  f"median: {statistics.median(vals):.3f}s | "
                  f"p90: {sorted(vals)[p90_idx]:.3f}s")
        else:
            print(f"{prefix}  {name}: N/A")


# =============================================================================
# Core benchmark
# =============================================================================

def run_single(
    idx: int,
    text: str,
    task: Task,
    config: TranslateConfig,
    start_time: float,
    active_counter: dict,
    submit_time: float = 0.0,
) -> BenchmarkResult:
    """Run a single benchmark iteration."""
    pending_time = time.time() - submit_time if submit_time > 0 else 0.0
    request_start = time.time()
    timing = None

    try:
        with active_counter['lock']:
            active_counter['count'] += 1

        # Use task.run() which returns TaskResult with output + timing
        result = task.run(text, config)
        output = result.output
        timing = result.timing

        with active_counter['lock']:
            active_counter['count'] -= 1

        duration = time.time() - request_start

        if not output or output.strip() == "":
            raise Exception("Empty output received")

        return BenchmarkResult(
            idx=idx,
            input_text=text[:100] + "..." if len(text) > 100 else text,
            duration=duration,
            success=True,
            output=output[:100] + "..." if len(output) > 100 else output,
            completed_at=time.time() - start_time,
            pending_time=pending_time,
            timing=timing
        )

    except Exception as e:
        with active_counter['lock']:
            active_counter['count'] -= 1

        duration = time.time() - request_start
        error_str = str(e)
        timed_out = "timeout" in error_str.lower()

        return BenchmarkResult(
            idx=idx,
            input_text=text[:100] + "..." if len(text) > 100 else text,
            duration=duration,
            success=False,
            error=error_str,
            timed_out=timed_out,
            completed_at=time.time() - start_time,
            pending_time=pending_time
        )


def run_benchmark(
    inputs: List[str],
    task: Task,
    config: TranslateConfig,
    concurrency: int,
    max_items: Optional[int] = None,
    stats_interval: int = 10,
    load_mode: str = "fixed",
    qps: Optional[float] = None,
    verbose: bool = False,
) -> List[BenchmarkResult]:
    """Run benchmark with specified concurrency.
    
    Load modes:
    - fixed: maintain fixed number of active requests
    - qps: emit requests at fixed rate (Poisson distribution)
    """
    if max_items:
        inputs = inputs[:max_items]

    print(f"\n{'=' * 70}")
    print(f"Starting benchmark:")
    print(f"  Task: {task.name} ({task.cache_key()})")
    print(f"  Endpoint: {config.endpoint}" + (" (Azure)" if config.use_azure else ""))
    print(f"  Model: {config.model}")
    print(f"  Total items: {len(inputs)}")
    if load_mode == "fixed":
        print(f"  Load mode: fixed ({concurrency} active)")
    else:
        print(f"  Load mode: QPS ({qps} queries/sec, max workers: {concurrency})")
    print(f"  Timeout: {config.timeout}s")
    print(f"{'=' * 70}\n")

    results = []
    results_lock = threading.Lock()
    active_counter = {'count': 0, 'lock': threading.Lock()}
    start_time = time.time()

    def get_active():
        with active_counter['lock']:
            return active_counter['count']

    def process_item(i: int, text: str, submit_time: float = 0.0):
        text = text.replace('RANDOM_SALT', str(random.randint(0, 999999)))
        
        result = run_single(i, text, task, config, start_time, active_counter, submit_time)
        
        speed = len(text) / result.duration if result.duration > 0 else 0
        active = get_active()
        
        # Format timing if available
        timing_str = ""
        if result.timing:
            parts = []
            client_oh, proxy_oh, worker_oh = result.timing.overheads()
            cd = result.timing.client_duration()
            if cd is not None and result.duration > 0:
                net_oh = result.duration - cd
                if net_oh > 0:
                    parts.append(f"N:{net_oh:.3f}s")
            if worker_oh > 0:
                parts.append(f"W:{worker_oh:.3f}s")
            if timing_str := " ".join(parts):
                timing_str = " | " + timing_str

        pending_str = f" | pending: {result.pending_time:.2f}s" if result.pending_time > 0 else ""
        
        if result.success:
            print(f"[{i+1}/{len(inputs)}] ✓ {result.duration:.2f}s{pending_str}{timing_str} | "
                  f"{len(text)} chars | {speed:.0f} c/s | active: {active}")
            if verbose:
                print(f"  In:  {text[:80]}...")
                print(f"  Out: {result.output}")
        else:
            timeout_marker = " [TIMEOUT]" if result.timed_out else ""
            print(f"[{i+1}/{len(inputs)}] ✗{timeout_marker} {result.duration:.2f}s | {result.error[:50]}")

        with results_lock:
            results.append(result)
            if len(results) % stats_interval == 0:
                print_stats(results, time.time() - start_time, len(inputs), inputs)

        return result

    # Execute based on load mode
    if load_mode == "fixed":
        idx = {'value': 0, 'lock': threading.Lock()}

        def worker():
            while True:
                with idx['lock']:
                    i = idx['value']
                    if i >= len(inputs):
                        break
                    idx['value'] += 1
                process_item(i, inputs[i])

        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(worker) for _ in range(concurrency)]
            for f in as_completed(futures):
                f.result()

    elif load_mode == "qps":
        # Generate Poisson-distributed request times
        request_times = []
        current_time = 0
        for _ in range(len(inputs)):
            current_time += random.expovariate(qps)
            request_times.append(current_time)

        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = []
            for scheduled_time, i in zip(request_times, range(len(inputs))):
                wait_time = scheduled_time - (time.time() - start_time)
                if wait_time > 0:
                    time.sleep(wait_time)
                submit_time = time.time()
                futures.append(executor.submit(process_item, i, inputs[i], submit_time))

            for f in as_completed(futures):
                f.result()

    total_duration = time.time() - start_time
    print_stats(results, total_duration, len(inputs), inputs, is_final=True)

    return results


def print_stats(
    results: List[BenchmarkResult],
    elapsed: float,
    total: int,
    all_inputs: List[str],
    is_final: bool = False
):
    """Print statistics."""
    successful = [r for r in results if r.success]
    failed = [r for r in results if not r.success]

    sep = '=' if is_final else '─'
    title = "FINAL RESULTS" if is_final else f"STATS ({len(results)}/{total}, {elapsed:.1f}s)"

    print(f"\n{sep * 70}")
    print(f"{title}:")
    print(f"  Successful: {len(successful)} | Failed: {len(failed)}")
    if is_final:
        print(f"  Total time: {elapsed:.2f}s")

    if successful:
        durations = [r.duration for r in successful]
        input_chars = sum(len(all_inputs[r.idx]) for r in successful)
        sorted_d = sorted(durations)

        print(f"\n  Throughput: {len(successful) / elapsed:.2f} req/s | {input_chars / elapsed:.0f} chars/s")
        print(f"  Latency: avg {statistics.mean(durations):.2f}s | "
              f"p50 {sorted_d[len(sorted_d)//2]:.2f}s | "
              f"p90 {sorted_d[int(len(sorted_d)*0.9)]:.2f}s | "
              f"p99 {sorted_d[int(len(sorted_d)*0.99)]:.2f}s")

        timing_stats = calculate_timing_stats(successful)
        if timing_stats:
            print()
            print_timing_breakdown(timing_stats, prefix="  ")

    print(f"{sep * 70}\n")


# =============================================================================
# CLI entry point
# =============================================================================

def cmd_benchmark(args):
    """CLI entry point for benchmark command."""
    from mt.tasks import get_task
    
    # Determine task
    task_name = getattr(args, 'task', 'translate') or 'translate'
    
    if task_name == 'translate':
        target_lang = getattr(args, 'target_lang', 'German (de)') or 'German (de)'
        # Parse source/target if provided as "en->de" or "German (de)"
        if '->' in target_lang:
            src, tgt = target_lang.split('->')
            task = get_task("translate", src=src.strip(), tgt=tgt.strip())
        else:
            # Assume English source, parse tgt from full name like "German (de)"
            import re
            match = re.search(r'\((\w+)\)', target_lang)
            tgt = match.group(1) if match else "de"
            task = get_task("translate", src="en", tgt=tgt)
    elif task_name == 'summarize':
        lang = getattr(args, 'lang', 'en') or 'en'
        task = get_task("summarize", lang=lang)
    elif task_name == 'audio_transcribe':
        # Audio transcription benchmark
        return cmd_benchmark_audio_transcribe(args)
    else:
        raise ValueError(f"Unknown task: {task_name}")
    
    # Prepare inputs
    query = getattr(args, 'query', None)
    query_file = getattr(args, 'query_file', None)
    log_file = getattr(args, 'log_file', None)
    chunk_length = getattr(args, 'chunk_length', 300) or 300
    max_items = getattr(args, 'max_chunks', None)
    
    if query or query_file:
        if query_file:
            with open(query_file, 'r', encoding='utf-8') as f:
                text = f.read()
            print(f"Query from file: {query_file} ({len(text)} chars)")
        else:
            text = query
            print(f"Query from CLI ({len(text)} chars)")
        
        repeat = max_items or 1000
        inputs = [text] * repeat
        
    elif log_file:
        print(f"Parsing log file: {log_file}")
        queries = parse_log_file(log_file)
        inputs = []
        for target_lang, texts in queries:
            inputs.extend(texts)
        print(f"Found {len(inputs)} queries")
        
    else:
        text = download_war_and_peace()
        inputs = split_into_chunks(text, chunk_length)
        print(f"Split into {len(inputs)} chunks")
    
    # Load config
    config = config_from_args(args)
    
    # Run benchmark
    concurrency = getattr(args, 'concurrency', 60) or 60
    stats_interval = getattr(args, 'stats_interval', 10) or 10
    load_mode = getattr(args, 'load_mode', 'fixed') or 'fixed'
    qps = getattr(args, 'qps', None)
    verbose = getattr(args, 'verbose', False)
    
    results = run_benchmark(
        inputs=inputs,
        task=task,
        config=config,
        concurrency=concurrency,
        max_items=max_items,
        stats_interval=stats_interval,
        load_mode=load_mode,
        qps=qps,
        verbose=verbose,
    )
    
    # Save CSV if requested
    csv_path = getattr(args, 'csv', None)
    if csv_path:
        save_results_csv(results, inputs, config.model, csv_path)


def cmd_benchmark_audio_transcribe(args):
    """Benchmark audio transcription speed and latency."""
    from pathlib import Path
    from mt import config_from_args
    from mt.tasks.audio_transcribe import AudioTranscribeTask
    
    # Get config
    config = config_from_args(args)
    endpoint = config.endpoint if config.endpoint else "http://127.0.0.1:8000"
    model = getattr(args, 'transcribe_model', None) or getattr(args, 'model', None) or 'openai/whisper-large-v3'
    timeout = config.timeout if config.timeout else 60
    language = getattr(args, 'transcribe_language', None)
    
    concurrency = getattr(args, 'concurrency', 60) or 60
    max_items = getattr(args, 'max_chunks', None)
    stats_interval = getattr(args, 'stats_interval', 10) or 10
    verbose = getattr(args, 'verbose', False)
    
    # Get audio inputs
    audio_dir = getattr(args, 'audio_dir', None)
    query_file = getattr(args, 'query_file', None)
    query = getattr(args, 'query', None)
    langs_str = getattr(args, 'langs', None)
    langs = [l.strip() for l in langs_str.split(',')] if langs_str else None
    
    # Collect audio files
    audio_files = []
    
    if query or query_file:
        # Single audio file to repeat
        audio_path = query_file or query
        if not Path(audio_path).exists():
            raise FileNotFoundError(f"Audio file not found: {audio_path}")
        repeat = max_items or 100
        audio_files = [audio_path] * repeat
        print(f"Benchmarking single audio file: {audio_path} (x{repeat})")
    
    elif audio_dir:
        # Load from directory
        audio_dir_path = Path(audio_dir)
        if not audio_dir_path.exists():
            raise FileNotFoundError(f"Audio directory not found: {audio_dir}")
        
        audio_extensions = {'.wav', '.mp3', '.flac', '.ogg', '.m4a', '.opus'}
        
        if langs:
            # Load from language subdirectories
            for lang in langs:
                lang_dir = audio_dir_path / lang
                if lang_dir.exists():
                    for f in sorted(lang_dir.iterdir()):
                        if f.suffix.lower() in audio_extensions:
                            audio_files.append(str(f))
        else:
            # Load all audio files (including subdirs)
            for f in sorted(audio_dir_path.rglob("*")):
                if f.suffix.lower() in audio_extensions:
                    audio_files.append(str(f))
        
        print(f"Found {len(audio_files)} audio files in {audio_dir}")
    
    else:
        raise ValueError(
            "Audio files required for transcription benchmark.\n"
            "Use --query-file <audio.wav> or --audio-dir <path>"
        )
    
    if max_items and len(audio_files) > max_items:
        audio_files = audio_files[:max_items]
    
    # Create task
    task = AudioTranscribeTask(
        endpoint=endpoint,
        model=model,
        timeout=timeout,
        language=language,
    )
    
    print(f"\n{'=' * 70}")
    print(f"Audio Transcription Benchmark:")
    print(f"  Endpoint: {endpoint}")
    print(f"  Model: {model}")
    if language:
        print(f"  Language: {language}")
    print(f"  Total files: {len(audio_files)}")
    print(f"  Concurrency: {concurrency}")
    print(f"  Timeout: {timeout}s")
    print(f"{'=' * 70}\n")
    
    # Run benchmark
    results = []
    results_lock = threading.Lock()
    active_counter = {'count': 0, 'lock': threading.Lock()}
    start_time = time.time()
    
    def get_active():
        with active_counter['lock']:
            return active_counter['count']
    
    def process_audio(i: int, audio_path: str):
        with active_counter['lock']:
            active_counter['count'] += 1
        
        request_start = time.time()
        
        try:
            result = task.run(audio_path, config=None)
            duration = time.time() - request_start
            
            with active_counter['lock']:
                active_counter['count'] -= 1
            
            output_len = len(result.output) if result.output else 0
            active = get_active()
            
            print(f"[{i+1}/{len(audio_files)}] ✓ {duration:.2f}s | "
                  f"{output_len} chars | active: {active}")
            if verbose and result.output:
                print(f"  Out: {result.output[:80]}...")
            
            return BenchmarkResult(
                idx=i,
                input_text=audio_path,
                duration=duration,
                success=True,
                output=result.output[:100] + "..." if result.output and len(result.output) > 100 else result.output,
                completed_at=time.time() - start_time,
            )
        
        except Exception as e:
            with active_counter['lock']:
                active_counter['count'] -= 1
            
            duration = time.time() - request_start
            error_str = str(e)
            timed_out = "timeout" in error_str.lower()
            
            timeout_marker = " [TIMEOUT]" if timed_out else ""
            print(f"[{i+1}/{len(audio_files)}] ✗{timeout_marker} {duration:.2f}s | {error_str[:50]}")
            
            return BenchmarkResult(
                idx=i,
                input_text=audio_path,
                duration=duration,
                success=False,
                error=error_str,
                timed_out=timed_out,
                completed_at=time.time() - start_time,
            )
    
    # Run with concurrency
    idx = {'value': 0, 'lock': threading.Lock()}
    
    def worker():
        while True:
            with idx['lock']:
                i = idx['value']
                if i >= len(audio_files):
                    break
                idx['value'] += 1
            
            result = process_audio(i, audio_files[i])
            
            with results_lock:
                results.append(result)
                if len(results) % stats_interval == 0:
                    print_stats(results, time.time() - start_time, len(audio_files), audio_files)
    
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(worker) for _ in range(concurrency)]
        for f in as_completed(futures):
            f.result()
    
    total_duration = time.time() - start_time
    print_stats(results, total_duration, len(audio_files), audio_files, is_final=True)
    
    # Save CSV if requested
    csv_path = getattr(args, 'csv', None)
    if csv_path:
        save_results_csv(results, audio_files, model, csv_path)
    
    return results


def save_results_csv(results: List[BenchmarkResult], inputs: List[str], model: str, path: str):
    """Save benchmark results to CSV."""
    hostname = socket.gethostname()
    
    fieldnames = ['idx', 'success', 'duration', 'input_chars', 'output_chars', 
                  'chars_per_sec', 'error', 'timestamp']
    
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for r in results:
            input_len = len(inputs[r.idx]) if r.idx < len(inputs) else 0
            output_len = len(r.output) if r.output else 0
            
            writer.writerow({
                'idx': r.idx,
                'success': r.success,
                'duration': f"{r.duration:.3f}",
                'input_chars': input_len,
                'output_chars': output_len,
                'chars_per_sec': f"{input_len / r.duration:.0f}" if r.duration > 0 else 0,
                'error': r.error or '',
                'timestamp': datetime.now().isoformat()
            })
    
    print(f"\nResults saved to: {path}")


# For standalone use
if __name__ == "__main__":
    import argparse
    from mt import add_translate_args
    
    parser = argparse.ArgumentParser(description='Benchmark LLM endpoint')
    add_translate_args(parser, include_concurrency=False)
    
    parser.add_argument('--task', choices=['translate', 'summarize'], default='translate')
    parser.add_argument('--lang', default='en', help='Language for summarize')
    parser.add_argument('--concurrency', type=int, default=60)
    parser.add_argument('--chunk-length', type=int, default=300)
    parser.add_argument('--target-lang', default='German (de)')
    parser.add_argument('--max-chunks', type=int)
    parser.add_argument('--stats-interval', type=int, default=10)
    parser.add_argument('--log-file', type=str)
    parser.add_argument('--load-mode', choices=['fixed', 'qps'], default='fixed')
    parser.add_argument('--qps', type=float)
    parser.add_argument('--query', type=str)
    parser.add_argument('--query-file', type=str)
    parser.add_argument('--csv', type=str)
    
    args = parser.parse_args()
    cmd_benchmark(args)
