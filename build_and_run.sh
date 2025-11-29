#!/bin/bash

# Quark - Build and Run Helper for WSL

echo "Checking for dependencies..."

# Check for GCC
if ! command -v gcc &> /dev/null; then
    echo "Installing GCC..."
    sudo apt-get update
    sudo apt-get install -y build-essential
fi

# Check for Ncurses
if ! dpkg -s libncurses-dev &> /dev/null; then
    echo "Installing Ncurses library..."
    sudo apt-get install -y libncurses-dev
fi

echo "Compiling Quark..."
gcc minicontainer_fixed.c -o quark -lncurses



if [ $? -eq 0 ]; then
    echo "Compilation successful!"
    echo "Launching Quark Monitor..."
    sudo ./quark monitor
else
    echo "Compilation failed."
    exit 1
fi
