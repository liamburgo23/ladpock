"""Local AI review: a model running on this computer (via Ollama) reads the
parts of a project most likely to hide logic bugs, overnight if you like.

Results are "leads", not findings: each must quote real code (checked before
it's kept), never changes the grade, and can never hide a scanner finding.
"""
