"""
Quality evaluation command.

Generic evaluator that works with any task (translate, summarize, etc).
"""

import json
import sys
import time
import csv
import re
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.table import Table

from mt import TranslateConfig, config_from_args
from mt.cache import TaskCache
from mt.tasks.base import Task, Sample


# =============================================================================
# Generic model evaluation
# =============================================================================

@dataclass
class EvalStats:
    """Stats for a single model evaluation."""
    executed: int = 0
    cached: int = 0
    errors: int = 0


def run_model_eval(
    task: Task,
    samples: List[Sample],
    config: TranslateConfig,
    cache: TaskCache,
    concurrency: int = 1,
    verbose: bool = False,
) -> Tuple[List[str], EvalStats, dict]:
    """Run evaluation for a single model on a single task.
    
    Returns:
        outputs: Model outputs (parallel to samples)
        stats: Execution statistics
        metrics: Aggregated metrics
    """
    outputs = [None] * len(samples)
    stats = EvalStats()
    stats_lock = threading.Lock()
    
    config_key = config.cache_key()
    model_tag = f"[{config_key}]"
    task_key = task.name
    params = json.loads(task.params_json())
    progress_label = task.format_progress(0, len(samples))
    
    def process_sample(i: int, sample: Sample):
        input_len = len(sample.input)
        
        # Check cache
        if not cache.rewrite:
            cached = cache.get(task_key, sample.input, config_key, params)
            if cached:
                outputs[i] = cached[0]
                output_len = len(cached[0])
                with stats_lock:
                    stats.cached += 1
                print(f"{model_tag} [{i+1}/{len(samples)}] {progress_label} ⚡ CACHED | {input_len} → {output_len} chars")
                return
        
        # Execute
        t0 = time.time()
        try:
            result = task.run(sample.input, config)
            duration = time.time() - t0
            output = result.output
            outputs[i] = output
            output_len = len(output) if output else 0
            cache.put(task_key, sample.input, config_key, output, duration, params)
            with stats_lock:
                stats.executed += 1
            print(f"{model_tag} [{i+1}/{len(samples)}] {progress_label} ✓ {duration:.2f}s | {input_len} → {output_len} chars")
        except Exception as e:
            duration = time.time() - t0
            with stats_lock:
                stats.errors += 1
            if verbose:
                import traceback
                traceback.print_exc()
            print(f"{model_tag} [{i+1}/{len(samples)}] {progress_label} ✗ {duration:.2f}s | Error: {e}")
    
    # Run with concurrency
    if concurrency > 1:
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = {executor.submit(process_sample, i, s): i for i, s in enumerate(samples)}
            for future in as_completed(futures):
                future.result()
    else:
        for i, sample in enumerate(samples):
            process_sample(i, sample)
    
    cache.save()
    print(f"\n{model_tag} Stats: {stats.executed} executed, {stats.cached} cached, {stats.errors} errors")
    
    # Compute scores
    metric_name = task.metric_name()
    print(f"{model_tag} Calculating {metric_name}...")
    scores = task.compute_scores_cached(samples, outputs, cache, metric_name)
    metrics = task.aggregate_scores(scores)
    
    # Print examples
    num_examples = 5 if verbose else 3
    print(f"\n{model_tag} Examples:")
    for i in range(min(num_examples, len(samples))):
        sample = samples[i]
        output = outputs[i]
        score = scores[i] if scores else None
        
        score_str = f"{metric_name}: {score:.3f}" if score is not None else f"{metric_name}: N/A"
        print(f"\n  [{i+1}] {score_str}")
        
        # Truncate for display
        input_preview = sample.input[:300].replace('\n', ' ')
        if len(sample.input) > 300:
            input_preview += "..."
        ref_preview = sample.reference[:200].replace('\n', ' ')
        if len(sample.reference) > 200:
            ref_preview += "..."
        out_preview = (output[:200].replace('\n', ' ') if output else "(none)")
        if output and len(output) > 200:
            out_preview += "..."
        
        print(f"      Input:     {input_preview}")
        print(f"      Reference: {ref_preview}")
        print(f"      Output:    {out_preview}")
    
    cache.save()
    return outputs, stats, metrics


# =============================================================================
# Language pair helpers
# =============================================================================

FLORES_LANGS = {"en", "ru", "zh", "es", "tr", "pt", "ko", "id", "ar", "fr", 
                "vi", "ja", "it", "fa", "de", "uk", "uz", "pl", "nl", "he",
                "cs", "hu", "sk", "sr", "th", "hi", "bn", "my", "el", "ro",
                "bg", "da", "fi", "no", "sv", "et", "lt", "lv", "sl", "hr"}


def parse_lang_pairs(pairs_str: str) -> List[Tuple[str, str]]:
    """Parse comma-separated language pairs: 'en-ru,en-zh'."""
    pairs = []
    for pair in pairs_str.split(","):
        pair = pair.strip()
        if "-" in pair:
            src, tgt = pair.split("-", 1)
            pairs.append((src.strip(), tgt.strip()))
    return pairs


def get_top_pairs_from_csv(csv_path: str, top_n: int = 20) -> Tuple[List[Tuple[str, str]], Dict[str, float]]:
    """Load top language pairs from traffic CSV."""
    pairs = []
    cumulative_pct = {}
    total_pct = 0.0
    
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            to_lang = row['to_lang']
            from_lang = row['from_lang']
            
            pct_match = re.search(r'\(([\d.]+)%\)', row.get('num_pct', ''))
            pct = float(pct_match.group(1)) if pct_match else 0.0
            
            if to_lang == from_lang:
                continue
            
            if from_lang in ("zh-CN", "zh-TW"):
                from_lang = "zh"
            if to_lang in ("zh-CN", "zh-TW"):
                to_lang = "zh"
            
            if from_lang not in FLORES_LANGS or to_lang not in FLORES_LANGS:
                continue
            
            total_pct += pct
            pair_key = f"{from_lang}->{to_lang}"
            pairs.append((from_lang, to_lang))
            cumulative_pct[pair_key] = total_pct
            
            if len(pairs) >= top_n:
                break
    
    return pairs, cumulative_pct


# =============================================================================
# Output formatting
# =============================================================================

def print_comparison_table(
    all_results: Dict[str, Dict[str, dict]],
    task_keys: List[str],
    metric_key: str,
    task_labels: Dict[str, float] = None,  # Optional cumulative % for translation
):
    """Print comparison table for multiple models across multiple tasks.
    
    Args:
        all_results: {model_name: {task_key: metrics}}
        task_keys: Ordered list of task keys
        metric_key: Which metric to display (e.g., 'comet', 'bertscore_f1')
        task_labels: Optional {task_key: cumulative_pct} for display
    """
    if len(all_results) < 2:
        return
    
    console = Console()
    model_names = list(all_results.keys())
    
    # Single task → simple comparison
    if len(task_keys) == 1:
        table = Table(title="COMPARISON", show_header=True, header_style="bold")
        table.add_column(metric_key.upper(), justify="right")
        table.add_column("Model", style="cyan")
        table.add_column("N", justify="right")
        
        scores = [(name, all_results[name].get(task_keys[0], {}).get(metric_key, 0) or 0,
                   all_results[name].get(task_keys[0], {}).get('n', 0))
                  for name in model_names]
        scores.sort(key=lambda x: x[1], reverse=True)
        best = scores[0][1] if scores else 0
        
        for name, score, n in scores:
            if score == best:
                score_str = f"[green]{score:.4f}[/green]"
            else:
                diff = ((score - best) / best * 100) if best else 0
                score_str = f"{score:.4f} ({diff:+.1f}%)"
            table.add_row(score_str, name, str(n))
        
        console.print(table)
        return
    
    # Multiple tasks → full comparison table
    table = Table(title=f"COMPARISON: {' vs '.join(model_names)}", 
                  show_header=True, header_style="bold")
    
    table.add_column("Task", style="cyan")
    for name in model_names:
        table.add_column(f"{name}\n{metric_key.upper()}", justify="right")
    
    def format_score(val, vals):
        best = max(vals) if vals else 0
        if val == best:
            return f"[green]{val:.4f}[/green]"
        diff = ((val - best) / best * 100) if best else 0
        return f"{val:.4f} ({diff:+.1f}%)"
    
    all_scores = {name: [] for name in model_names}
    
    for task_key in task_keys:
        label = task_key
        if task_labels and task_key in task_labels:
            label = f"{task_key} ({task_labels[task_key]:.0f}%)"
        
        scores = []
        for name in model_names:
            s = all_results.get(name, {}).get(task_key, {}).get(metric_key, 0) or 0
            scores.append(s)
            all_scores[name].append(s)
        
        row = [label] + [format_score(s, scores) for s in scores]
        table.add_row(*row)
    
    # Average row
    table.add_section()
    avg_scores = [sum(all_scores[n]) / len(all_scores[n]) if all_scores[n] else 0 
                  for n in model_names]
    table.add_row("AVERAGE", *[format_score(s, avg_scores) for s in avg_scores], style="bold")
    
    console.print(table)


# =============================================================================
# Unified evaluation
# =============================================================================

def run_evaluation(
    tasks: List[Task],
    configs: List[TranslateConfig],
    cache: TaskCache,
    num_samples: int,
    concurrency: int,
    verbose: bool,
    metric_key: str,
    task_labels: Dict[str, float] = None,
):
    """Run evaluation for multiple tasks × multiple models.
    
    Returns:
        all_results: {model_name: {task_key: metrics}}
    """
    all_results: Dict[str, Dict[str, dict]] = {}
    task_keys = [t.cache_key() for t in tasks]
    
    for config in configs:
        model_name = config.cache_key()
        all_results[model_name] = {}
        
        print(f"\n{'#'*70}")
        print(f"# {model_name}")
        print(f"{'#'*70}")
        
        for task in tasks:
            task_key = task.cache_key()
            print(f"\n{'='*70}")
            print(f"Evaluating {task_key}")
            print(f"{'='*70}")
            
            try:
                samples = task.load_eval_data(n=num_samples)
            except Exception as e:
                print(f"Failed to load data for {task_key}: {e}")
                continue
            
            outputs, stats, metrics = run_model_eval(
                task=task,
                samples=samples,
                config=config,
                cache=cache,
                concurrency=concurrency,
                verbose=verbose,
            )
            
            all_results[model_name][task_key] = metrics
            
            # Print primary metric
            primary_val = metrics.get(metric_key)
            if primary_val is not None:
                print(f"\n{task_key}: {metric_key} = {primary_val:.4f}")
        
        # Print model summary
        if len(tasks) > 1:
            console = Console()
            table = Table(title=f"SUMMARY: {model_name}", show_header=True, header_style="bold")
            table.add_column("Task", style="cyan")
            table.add_column(metric_key.upper(), justify="right")
            table.add_column("N", justify="right")
            
            for task_key in task_keys:
                metrics = all_results[model_name].get(task_key, {})
                val = metrics.get(metric_key)
                n = metrics.get('n', 0)
                val_str = f"{val:.4f}" if val is not None else "N/A"
                table.add_row(task_key, val_str, str(n))
            
            console.print(table)
    
    # Comparison
    if len(configs) >= 2:
        print_comparison_table(all_results, task_keys, metric_key, task_labels)
    
    return all_results


# =============================================================================
# CLI entry point
# =============================================================================

def cmd_eval(args):
    """CLI entry point for eval command."""
    from mt.tasks import get_task
    
    # Create cache
    cache_path = getattr(args, 'cache', 'translation_cache.duckdb')
    no_cache = getattr(args, 'no_cache', False)
    rewrite = getattr(args, 'rewrite', False) or getattr(args, 'rewrite_cache', False)
    cache = TaskCache(cache_path if not no_cache else None, rewrite=rewrite)
    
    num_samples = getattr(args, 'num_samples', None) or getattr(args, 'n', None) or 100
    concurrency = getattr(args, 'concurrency', 1) or 1
    verbose = getattr(args, 'verbose', False)
    
    # Load configs
    configs = []
    config_files = getattr(args, 'configs', None) or []
    if config_files:
        for config_path in config_files:
            config = config_from_args(args, config_path=config_path)
            configs.append(config)
    else:
        configs.append(config_from_args(args))
    
    # Dispatch based on task type
    task_name = getattr(args, 'task', 'translate') or 'translate'
    task_labels = None
    
    if task_name == 'audio_langid':
        # Audio language identification - special handling
        return cmd_eval_audio_langid(args, cache, num_samples, verbose)
    
    if task_name == 'audio_transcribe':
        # Audio transcription - special handling
        return cmd_eval_audio_transcribe(args, cache, num_samples, concurrency, verbose)
    
    if task_name == 'summarize':
        lang = getattr(args, 'lang', 'en') or 'en'
        tasks = [get_task("summarize", lang=lang)]
        metric_key = 'bertscore_f1'
        
        print(f"\n{'='*70}")
        print(f"Summarization Evaluation: {lang}")
        print(f"{'='*70}")
        
    else:  # translate
        comet_model = getattr(args, 'comet_model', 'wmt22') or 'wmt22'
        
        # Determine language pairs
        if args.pairs:
            pairs = parse_lang_pairs(args.pairs)
            cumulative_pct = {}
        elif getattr(args, 'from_csv', None):
            top_pairs = getattr(args, 'top_pairs', 10)
            pairs, cumulative_pct = get_top_pairs_from_csv(args.from_csv, top_pairs)
            print(f"Loaded {len(pairs)} pairs from {args.from_csv}")
        else:
            pairs = [("en", "ru"), ("en", "zh"), ("ru", "en"), ("en", "es")]
            cumulative_pct = {}
            print(f"Using {len(pairs)} default pairs")
        
        if not pairs:
            sys.exit("No language pairs to evaluate!")
        
        tasks = [get_task("translate", src=src, tgt=tgt, comet_model=comet_model) 
                 for src, tgt in pairs]
        metric_key = 'comet'
        task_labels = {f"translate:{src}->{tgt}": cumulative_pct.get(f"{src}->{tgt}", 0) 
                       for src, tgt in pairs if f"{src}->{tgt}" in cumulative_pct}
        
        print(f"\n{'='*70}")
        print(f"Translation Evaluation: {len(pairs)} pairs")
        print(f"{'='*70}")
        for src, tgt in pairs:
            pct = cumulative_pct.get(f"{src}->{tgt}")
            if pct:
                print(f"  {src} -> {tgt} (cumul: {pct:.1f}%)")
            else:
                print(f"  {src} -> {tgt}")
    
    print(f"\nModels ({len(configs)}):")
    for c in configs:
        print(f"  - {c.cache_key()}")
    print(f"Samples: {num_samples}, Concurrency: {concurrency}")
    
    # Run evaluation
    all_results = run_evaluation(
        tasks=tasks,
        configs=configs,
        cache=cache,
        num_samples=num_samples,
        concurrency=concurrency,
        verbose=verbose,
        metric_key=metric_key,
        task_labels=task_labels,
    )
    
    # Save results
    output = getattr(args, 'output', None)
    if output:
        with open(output, 'w') as f:
            json.dump(all_results, f, indent=2)
        print(f"\nResults saved to {output}")


def cmd_eval_audio_langid(args, cache: TaskCache, num_samples: int, verbose: bool):
    """Evaluate audio language identification with per-language metrics."""
    from mt.tasks import get_task
    from mt.tasks.audio_langid import AudioLangIdTask
    
    audio_dir = getattr(args, 'audio_dir', None)
    langs_str = getattr(args, 'langs', None)
    langs = [l.strip() for l in langs_str.split(',')] if langs_str else None
    
    # If no audio_dir but langs specified, use Common Voice
    if not audio_dir and not langs:
        sys.exit(
            "Either --audio-dir or --langs is required for audio_langid.\n\n"
            "Option 1: Use local audio files:\n"
            "  ./mt eval --task audio_langid --audio-dir ./audio_data\n"
            "  (Expected structure: audio_dir/{lang}/*.wav)\n\n"
            "Option 2: Download from Common Voice dataset:\n"
            "  ./mt eval --task audio_langid --langs en,ru,zh,de,fr -n 50"
        )
    
    print(f"\n{'='*70}")
    print(f"Audio Language Identification Evaluation")
    print(f"{'='*70}")
    if audio_dir:
        print(f"Audio directory: {audio_dir}")
    else:
        print(f"Data source: Common Voice (fixie-ai/common_voice_17_0)")
    if langs:
        print(f"Languages: {', '.join(langs)}")
    print(f"Samples per language: {num_samples}")
    
    # Create task
    audio_model = getattr(args, 'audio_model', 'speechbrain') or 'speechbrain'
    task = AudioLangIdTask(model=audio_model, audio_dir=audio_dir, langs=langs, top_k=5)
    print(f"Model: {audio_model}")
    
    # Load samples
    try:
        samples = task.load_eval_data(n=num_samples)
    except Exception as e:
        sys.exit(f"Failed to load audio data: {e}")
    
    # Run predictions
    outputs = []
    for i, sample in enumerate(samples):
        lang = sample.meta.get("lang", "?")
        print(f"[{i+1}/{len(samples)}] {lang}: {sample.meta.get('file', '?')}", end=" ")
        try:
            result = task.run(sample.input, config=None)
            outputs.append(result.output)
            
            # Show prediction with color
            pred = result.output
            correct = pred.lower() == sample.reference.lower()
            if correct:
                print(f"→ {pred} ✓")
            else:
                print(f"→ {pred} ✗ (expected {sample.reference})")
        except Exception as e:
            outputs.append(None)
            print(f"→ ERROR: {e}")
            if verbose:
                import traceback
                traceback.print_exc()
    
    # Compute and print per-language metrics
    task.print_eval_report(samples, outputs)
    
    # Get metrics for saving
    scores = task.compute_scores(samples, outputs)
    metrics = task.aggregate_scores(scores)
    
    # Save results
    output = getattr(args, 'output', 'audio_langid_results.json')
    if output:
        full_metrics = {
            "overall": metrics,
            "per_lang_detailed": task.compute_per_language_metrics(samples, outputs),
            "samples_per_lang": num_samples,
            "audio_dir": audio_dir,
        }
        with open(output, 'w') as f:
            json.dump(full_metrics, f, indent=2)
        print(f"\nResults saved to {output}")


def cmd_eval_audio_transcribe(args, cache: TaskCache, num_samples: int, concurrency: int, verbose: bool):
    """Evaluate audio transcription with WER metrics."""
    from mt.tasks.audio_transcribe import AudioTranscribeTask
    from mt import config_from_args
    
    audio_dir = getattr(args, 'audio_dir', None)
    langs_str = getattr(args, 'langs', None)
    langs = [l.strip() for l in langs_str.split(',')] if langs_str else None
    
    # If no audio_dir but langs specified, use Common Voice
    if not audio_dir and not langs:
        sys.exit(
            "Either --audio-dir or --langs is required for audio_transcribe.\n\n"
            "Option 1: Use local audio files:\n"
            "  ./mt eval --task audio_transcribe --audio-dir ./audio_data\n"
            "  (Expected structure: audio_dir/{lang}/*.wav with matching .txt files)\n\n"
            "Option 2: Download from Common Voice dataset:\n"
            "  ./mt eval --task audio_transcribe --langs en,ru,zh -n 50"
        )
    
    # Get endpoint from config or args
    config = config_from_args(args)
    endpoint = config.endpoint if config.endpoint else "http://127.0.0.1:8000"
    model = getattr(args, 'transcribe_model', 'openai/whisper-large-v3') or 'openai/whisper-large-v3'
    timeout = config.timeout if config.timeout else 60
    
    print(f"\n{'='*70}")
    print(f"Audio Transcription Evaluation")
    print(f"{'='*70}")
    print(f"Endpoint: {endpoint}")
    print(f"Model: {model}")
    if audio_dir:
        print(f"Audio directory: {audio_dir}")
    else:
        print(f"Data source: Common Voice (fixie-ai/common_voice_17_0)")
    if langs:
        print(f"Languages: {', '.join(langs)}")
    print(f"Samples per language: {num_samples}")
    print(f"Concurrency: {concurrency}")
    
    # Create task
    task = AudioTranscribeTask(
        endpoint=endpoint,
        model=model,
        audio_dir=audio_dir,
        langs=langs,
        timeout=timeout,
    )
    
    # Load samples
    try:
        samples = task.load_eval_data(n=num_samples)
    except Exception as e:
        sys.exit(f"Failed to load audio data: {e}")
    
    # Run predictions with concurrency
    outputs = [None] * len(samples)
    
    if concurrency > 1:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import threading
        
        lock = threading.Lock()
        completed = {'count': 0}
        
        def process_sample(i, sample):
            lang = sample.meta.get("lang", "?")
            try:
                # Pass language hint from sample metadata
                result = task.run(sample.input, config=None, language=lang if lang != "?" else None)
                output = result.output
                
                with lock:
                    completed['count'] += 1
                    count = completed['count']
                
                # Show result
                ref_preview = sample.reference[:50] + "..." if len(sample.reference) > 50 else sample.reference
                out_preview = output[:50] + "..." if len(output) > 50 else output
                print(f"[{count}/{len(samples)}] {lang}: {result.duration:.2f}s")
                if verbose:
                    print(f"  Ref: {ref_preview}")
                    print(f"  Out: {out_preview}")
                
                return i, output
            except Exception as e:
                with lock:
                    completed['count'] += 1
                    count = completed['count']
                print(f"[{count}/{len(samples)}] {lang}: ERROR - {e}")
                return i, None
        
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = {executor.submit(process_sample, i, s): i for i, s in enumerate(samples)}
            for future in as_completed(futures):
                i, output = future.result()
                outputs[i] = output
    else:
        # Sequential processing
        for i, sample in enumerate(samples):
            lang = sample.meta.get("lang", "?")
            print(f"[{i+1}/{len(samples)}] {lang}: {sample.meta.get('file', '?')}", end=" ")
            try:
                # Pass language hint from sample metadata
                result = task.run(sample.input, config=None, language=lang if lang != "?" else None)
                outputs[i] = result.output
                
                # Show result preview
                ref_preview = sample.reference[:40] + "..." if len(sample.reference) > 40 else sample.reference
                out_preview = result.output[:40] + "..." if len(result.output) > 40 else result.output
                print(f"→ {result.duration:.2f}s")
                if verbose:
                    print(f"      Ref: {ref_preview}")
                    print(f"      Out: {out_preview}")
            except Exception as e:
                outputs[i] = None
                print(f"→ ERROR: {e}")
                if verbose:
                    import traceback
                    traceback.print_exc()
    
    # Compute and print per-language metrics
    task.print_eval_report(samples, outputs)
    
    # Get metrics for saving
    scores = task.compute_scores(samples, outputs)
    metrics = task.aggregate_scores(scores)
    
    # Save results
    output = getattr(args, 'output', 'audio_transcribe_results.json')
    if output:
        full_metrics = {
            "overall": metrics,
            "per_lang_detailed": task.compute_per_language_metrics(samples, outputs),
            "samples_per_lang": num_samples,
            "endpoint": endpoint,
            "model": model,
            "audio_dir": audio_dir,
        }
        with open(output, 'w') as f:
            json.dump(full_metrics, f, indent=2)
        print(f"\nResults saved to {output}")
