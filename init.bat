@echo off

set VENV_NAME=sondare_venv

python -m venv %VENV_NAME%
call %VENV_NAME%\Scripts\activate

pip install -e .

echo Virtual environment '%VENV_NAME%' is set up and activated.
echo Run 'sondare --help' to get started.
