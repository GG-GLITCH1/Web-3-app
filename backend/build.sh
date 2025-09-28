#!/usr/bin/env bash
echo "🔄 Force Python version change..."
python --version

# Install exact Python version
pyenv install 3.11.4 -s
pyenv global 3.11.4

echo "✅ Using Python:"
python --version

# Install dependencies
pip install -r requirements.txt
