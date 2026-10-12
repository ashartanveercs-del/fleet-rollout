"""How the engine reaches a target: a small file-and-command interface with adapters."""

from .base import CommandResult, Executor, ExecutorError, HttpResponse, PathInfo

__all__ = ["CommandResult", "Executor", "ExecutorError", "HttpResponse", "PathInfo"]
