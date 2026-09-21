# Resolve how uv is invoked on this machine, and export it as $UV.
#
# uv ships either as a standalone binary on PATH or as a Python module. Hard-coding
# `python -m uv` worked on the machine these scripts were written on and failed on a
# teammate's, which silently broke every documented reproduction command. Source this
# instead of guessing.
if command -v uv >/dev/null 2>&1; then
  UV="uv"
elif python -m uv --version >/dev/null 2>&1; then
  UV="python -m uv"
elif python3 -m uv --version >/dev/null 2>&1; then
  UV="python3 -m uv"
else
  echo "uv not found. Install it: pip install uv   (or see https://docs.astral.sh/uv/)" >&2
  exit 1
fi
export UV
