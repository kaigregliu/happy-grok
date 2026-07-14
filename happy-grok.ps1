$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonScript = Join-Path $ScriptDir "happy_grok.py"

python $PythonScript @args
exit $LASTEXITCODE
