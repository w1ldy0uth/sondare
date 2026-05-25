@echo off

set VENV_NAME=netscan_venv

python -m venv %VENV_NAME%
call %VENV_NAME%\Scripts\activate

pip install -e .

echo Virtual environment '%VENV_NAME%' is set up and activated.
echo Run 'netscan --help' to get started.
