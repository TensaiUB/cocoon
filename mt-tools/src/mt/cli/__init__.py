"""
mt - Machine Translation CLI

Unified entry point for:
- mt run translate "text" --to ru --config azure.conf
- mt eval azure.conf local.conf --pairs en-ru --num-samples 50
- mt benchmark --config local.conf --concurrency 60
"""

import sys
import argparse

from mt import add_translate_args
from mt.tasks import list_tasks, AUDIO_TASKS

from .run import cmd_run
from .eval import cmd_eval
from .benchmark import cmd_benchmark


def main():
    parser = argparse.ArgumentParser(
        prog="mt",
        description="Machine Translation CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single translation
  mt run translate "Hello world" --to ru --config configs/azure.conf
  
  # Quality evaluation (compare models)
  mt eval configs/azure.conf configs/local.conf --pairs en-ru,ru-en -n 50 -c 50
  
  # Speed benchmark
  mt benchmark --config configs/local.conf --concurrency 60
"""
    )
    subparsers = parser.add_subparsers(dest="cmd", required=True)
    
    available_tasks = list_tasks()
    
    # =========================================================================
    # mt run <task> [input] [options]
    # =========================================================================
    p_run = subparsers.add_parser("run", help="Run single inference")
    p_run.add_argument("task", choices=available_tasks, help="Task to run")
    p_run.add_argument("input", nargs="?", help="Text to process (or use --file/stdin). For audio tasks, this is the audio file path.")
    p_run.add_argument("--file", "-f", help="Read input from file (text file for text tasks, audio file for audio tasks)")
    p_run.add_argument("--raw", action="store_true", help="Send raw JSON payload from --file or stdin directly to API")
    p_run.add_argument("--to", help="Target language for translate (e.g. 'ru')")
    p_run.add_argument("--lang", help="Language for summarize (default: en)")
    p_run.add_argument("--top-k", type=int, default=5, help="Number of top predictions for audio_langid (default: 5)")
    add_translate_args(p_run)
    p_run.set_defaults(func=cmd_run)
    
    # =========================================================================
    # mt eval [configs...] [options]
    # Matches scripts/quality_eval.py args
    # =========================================================================
    p_eval = subparsers.add_parser("eval", help="Quality evaluation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  mt eval azure.conf --pairs en-ru
  mt eval azure.conf local.conf --pairs en-ru,en-zh -n 50
  mt eval azure.conf --from-csv data/lang.csv --top-pairs 10 -c 50
""")
    p_eval.add_argument('configs', nargs='*', metavar='CONFIG',
                        help='Config file(s) to evaluate (INI format)')
    p_eval.add_argument('--task', type=str, default='translate',
                        choices=['translate', 'summarize', 'audio_langid', 'audio_transcribe'],
                        help='Task to evaluate (default: translate)')
    p_eval.add_argument('--lang', type=str, default='en',
                        help='Language for summarize task (default: en)')
    p_eval.add_argument('--audio-dir', type=str,
                        help='Directory with audio files for audio_langid (structure: dir/{lang}/*.wav)')
    p_eval.add_argument('--langs', type=str,
                        help='Comma-separated language codes for audio_langid (e.g., "en,ru,zh")')
    p_eval.add_argument('--audio-model', type=str, default='speechbrain',
                        help='Model for audio_langid: "speechbrain" or "whisper" (default: speechbrain)')
    p_eval.add_argument('--transcribe-model', type=str, default='openai/whisper-large-v3',
                        help='Model for audio_transcribe (default: openai/whisper-large-v3)')
    p_eval.add_argument('--transcribe-language', type=str,
                        help='Language hint for audio_transcribe (e.g., "en", "ru"). Auto-detected from sample if not set.')
    p_eval.add_argument('--pairs', type=str,
                        help='Language pairs for translate: en-ru,en-zh')
    p_eval.add_argument('--from-csv', type=str,
                        help='Load top pairs from lang.csv')
    p_eval.add_argument('--top-pairs', type=int, default=10,
                        help='Number of top pairs from CSV')
    p_eval.add_argument('-n', '--num-samples', type=int, default=100,
                        help='Samples per language pair')
    p_eval.add_argument('-c', '--concurrency', type=int, default=1,
                        help='Concurrent translation requests')
    p_eval.add_argument('-o', '--output', type=str, default='quality_results.json',
                        help='Output file for results')
    p_eval.add_argument('--cache', type=str, default='translation_cache.duckdb',
                        help='Cache file')
    p_eval.add_argument('--no-cache', action='store_true',
                        help='Disable caching')
    p_eval.add_argument('--rewrite-cache', action='store_true',
                        help='Ignore cached, rewrite')
    p_eval.add_argument('--comet-model', type=str, default='wmt22',
                        choices=['wmt22', 'xcomet-xl', 'xcomet-xxl'],
                        help='COMET model')
    add_translate_args(p_eval)  # Adds --verbose, --config, etc.
    p_eval.set_defaults(func=cmd_eval)
    
    # =========================================================================
    # mt benchmark [options]
    # Matches scripts/translation_benchmark.py args
    # =========================================================================
    p_bench = subparsers.add_parser("benchmark", help="Speed/latency benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  mt benchmark --config local.conf --concurrency 60
  mt benchmark --config azure.conf --load-mode qps --qps 10
  mt benchmark --query "Hello world" --max-chunks 100
""")
    add_translate_args(p_bench, include_concurrency=False)
    p_bench.add_argument('--task', choices=available_tasks, default='translate',
                         help='Task to benchmark')
    p_bench.add_argument('--lang', default='en',
                         help='Language for summarize task')
    p_bench.add_argument('--concurrency', type=int, default=60,
                         help='Concurrent requests (or max workers for QPS)')
    p_bench.add_argument('--chunk-length', type=int, default=300,
                         help='Chunk length for War and Peace')
    p_bench.add_argument('--target-lang', default='German (de)',
                         help='Target language')
    p_bench.add_argument('--max-chunks', type=int,
                         help='Max chunks to process')
    p_bench.add_argument('--single-query', action='store_true',
                         help='Translate entire file as one query')
    p_bench.add_argument('--stats-interval', type=int, default=10,
                         help='Print stats every N requests')
    p_bench.add_argument('--log-file', type=str,
                         help='Parse queries from log file')
    p_bench.add_argument('--load-mode', default='fixed',
                         choices=['fixed', 'qps'],
                         help='Load mode: fixed or qps')
    p_bench.add_argument('--qps', type=float,
                         help='Target QPS (for --load-mode qps)')
    p_bench.add_argument('--query', type=str,
                         help='Single query to repeat')
    p_bench.add_argument('--query-file', type=str,
                         help='Read query from file')
    p_bench.add_argument('--csv', type=str,
                         help='Save results to CSV')
    # Audio transcription options
    p_bench.add_argument('--audio-dir', type=str,
                         help='Directory with audio files for audio_transcribe benchmark')
    p_bench.add_argument('--langs', type=str,
                         help='Comma-separated language codes for audio (e.g., "en,ru,zh")')
    p_bench.add_argument('--transcribe-model', type=str, default='openai/whisper-large-v3',
                         help='Model for audio_transcribe (default: openai/whisper-large-v3)')
    p_bench.add_argument('--transcribe-language', type=str,
                         help='Language hint for audio_transcribe (e.g., "en", "ru")')
    p_bench.set_defaults(func=cmd_benchmark)
    
    # Parse and dispatch
    args = parser.parse_args()
    
    try:
        args.func(args)
    except KeyboardInterrupt:
        sys.exit("\nCancelled.")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if hasattr(args, 'verbose') and args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
