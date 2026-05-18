param(
    [int]$Port = 8000
)

$ErrorActionPreference = "Stop"
python -m backend.cli --host 127.0.0.1 --port $Port --reload
