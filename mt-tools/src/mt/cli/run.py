"""Run commands - single inference."""

import sys
import time
import json

from mt import config_from_args
from mt.tasks import get_task, is_audio_task


def get_input_text(args) -> str:
    """Get input text from args.input, args.file, or stdin."""
    if args.input:
        return args.input
    elif args.file:
        with open(args.file, 'r', encoding='utf-8') as f:
            return f.read().strip()
    else:
        if sys.stdin.isatty():
            print('Paste text (Ctrl+D when done):', file=sys.stderr)
        return sys.stdin.read().strip()


def get_audio_path(args) -> str:
    """Get audio file path from args.input or args.file."""
    path = args.input or args.file
    if not path:
        sys.exit("Audio file path is required. Provide as argument or use --file.")
    return path


def cmd_run(args):
    """Run single inference for any task."""
    
    # Handle --raw mode: send JSON payload directly to API
    if getattr(args, 'raw', False):
        return cmd_run_raw(args)
    
    # Handle audio tasks differently
    if is_audio_task(args.task):
        return cmd_run_audio(args)
    
    text = get_input_text(args)
    if not text:
        sys.exit("No text provided.")
    
    config = config_from_args(args)
    
    # Create task with appropriate params
    if args.task == "translate":
        if not args.to:
            sys.exit("--to is required for translate task")
        task = get_task("translate", src="en", tgt=args.to)
    elif args.task == "summarize":
        lang = args.lang or "en"
        task = get_task("summarize", lang=lang)
    else:
        sys.exit(f"Unknown task: {args.task}")
    
    if args.verbose:
        print(f"Running {task.name}...", file=sys.stderr)
        print(f"  Config: {task.cache_key()}", file=sys.stderr)
        print(f"  Endpoint: {config.endpoint}" + (" (Azure)" if config.use_azure else ""), file=sys.stderr)
    
    start = time.time()
    result = task.run(text, config)
    duration = time.time() - start
    
    if args.verbose:
        print(f"  Time: {duration:.3f}s", file=sys.stderr)
    
    print(result.output)


def cmd_run_raw(args):
    """Send raw JSON payload directly to API."""
    config = config_from_args(args)
    
    # Read JSON from --file or stdin
    if args.file:
        with open(args.file, 'r', encoding='utf-8') as f:
            payload = json.load(f)
    else:
        payload = json.load(sys.stdin)
    
    # Determine endpoint (completions vs chat based on payload)
    if "messages" in payload:
        url = f"{config.endpoint}/v1/chat/completions"
    else:
        url = f"{config.endpoint}/v1/completions"
    
    if args.verbose:
        print(f"Sending raw request to {url}", file=sys.stderr)
        print(f"  Model: {payload.get('model', 'N/A')}", file=sys.stderr)
    
    start = time.time()
    response = config.post(url, payload)
    duration = time.time() - start
    
    if args.verbose:
        print(f"  Time: {duration:.3f}s", file=sys.stderr)
        print(f"  Status: {response.status_code}", file=sys.stderr)
    
    response.raise_for_status()
    result = response.json()
    
    # Extract text from response
    if "choices" in result:
        choice = result["choices"][0]
        if "message" in choice:
            output = choice["message"]["content"]
        elif "text" in choice:
            output = choice["text"]
        else:
            output = json.dumps(result, indent=2)
    else:
        output = json.dumps(result, indent=2)
    
    print(output)


def cmd_run_audio(args):
    """Run audio task (audio_langid, audio_transcribe, etc.)."""
    audio_path = get_audio_path(args)
    
    # Create audio task
    if args.task == "audio_langid":
        top_k = getattr(args, 'top_k', 5)
        task = get_task("audio_langid", top_k=top_k)
    else:
        sys.exit(f"Unknown audio task: {args.task}")
    
    if args.verbose:
        print(f"Running {task.name}...", file=sys.stderr)
        print(f"  Audio: {audio_path}", file=sys.stderr)
    
    start = time.time()
    result = task.run(audio_path, config=None)
    duration = time.time() - start
    
    if args.verbose:
        print(f"  Time: {duration:.3f}s", file=sys.stderr)
    
    # Print language predictions
    print(f"Detected language: {result.output}")
    if "predictions" in result.meta:
        print("\nTop predictions:")
        for lang, prob in result.meta["predictions"]:
            print(f"  {lang}: {prob:.2%}")
