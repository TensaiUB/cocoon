"""Task registry for mt CLI."""

from mt.tasks.base import Task, Sample, TaskResult
from mt.tasks.translate import TranslateTask
from mt.tasks.summarize import SummarizeTask
from mt.tasks.audio_langid import AudioLangIdTask
from mt.tasks.audio_transcribe import AudioTranscribeTask

# Registry of task classes (not instances)
TASK_CLASSES = {
    "translate": TranslateTask,
    "summarize": SummarizeTask,
    "audio_langid": AudioLangIdTask,
    "audio_transcribe": AudioTranscribeTask,
}

# Tasks that work with audio files instead of text
AUDIO_TASKS = {"audio_langid", "audio_transcribe"}


def get_task(name: str, **kwargs) -> Task:
    """Create task instance with given parameters.
    
    Examples:
        task = get_task("translate", src="en", tgt="ru")
        task = get_task("summarize", lang="en")
        task = get_task("audio_langid", top_k=5)
    """
    if name not in TASK_CLASSES:
        raise ValueError(f"Unknown task: {name}. Available: {list(TASK_CLASSES.keys())}")
    return TASK_CLASSES[name](**kwargs)


def list_tasks():
    """List all available task names."""
    return list(TASK_CLASSES.keys())


def is_audio_task(name: str) -> bool:
    """Check if task processes audio files."""
    return name in AUDIO_TASKS


__all__ = [
    "Task", "Sample", "TaskResult", "get_task", "list_tasks", 
    "is_audio_task", "AUDIO_TASKS",
    "TranslateTask", "SummarizeTask", "AudioLangIdTask", "AudioTranscribeTask"
]
