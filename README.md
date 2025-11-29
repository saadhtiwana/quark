# Quark Container Runtime 🚀

![Quark Demo](demo.png)

**Quark** is a lightweight, zero-dependency container runtime written in C. It demonstrates the core principles of containerization (Namespaces, Cgroups, Chroot) in a single, readable codebase.

Think of it as a "Mini Docker" that you can build and run in seconds. It is designed for educational purposes, OS enthusiasts, and anyone who wants to understand how containers *actually* work under the hood.

---

## 🧐 What is Quark?

Quark is a minimal container engine. Unlike Docker or Podman which are complex distributed systems, Quark is a **single C file** that interacts directly with the Linux Kernel to create isolated environments.

### Why use it?
*   **Education**: Learn how `clone()`, `unshare()`, and `cgroups` work.
*   **Simplicity**: No daemons, no background services, no complex configuration.
*   **Speed**: Starts containers in milliseconds.
*   **Zero Dependencies**: Compiles with just `gcc` and `make`.

---

## ✨ Features

*   **🛡️ Process Isolation**: Uses Linux Namespaces (`PID`, `UTS`, `IPC`, `MNT`) to ensure containers cannot see or affect host processes.
*   **🧠 Resource Control**: Limits CPU usage and Memory for each container using Cgroups (supports both v1 and v2).
*   **📂 Filesystem Isolation**: Uses `chroot` and **Bind Mounts** to provide a full Linux rootfs sharing the host's binaries (`/bin`, `/lib`, `/usr`).
*   **🖥️ Interactive TUI**: A "Hacker-style" ncurses dashboard to create, run, and manage containers with keyboard shortcuts.
*   **🐍 Multi-Language Support**: Run Python, C, Bash, or any interpreter installed on your host system inside the container.

---

## 🛠️ Installation

### Prerequisites
*   **Operating System**: Linux or **WSL2** (Windows Subsystem for Linux).
    *   *Note: This will NOT run on standard Windows Command Prompt.*
*   **Compiler**: `gcc`
*   **Libraries**: `libncurses-dev` (for the interface)

### Step-by-Step Guide

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/saadhtiwana/quark.git
    cd quark
    ```

2.  **Build and Run (Automatic):**
    We provide a helper script that installs dependencies (on Debian/Ubuntu), compiles the code, and launches the runtime.
    ```bash
    bash build_and_run.sh
    ```

3.  **Manual Build:**
    If you prefer to build it yourself:
    ```bash
    gcc minicontainer_fixed.c -o quark -lncurses
    sudo ./quark monitor
    ```

---

## 🎮 Usage Manual

Once the **Quark Monitor** is running, you have full control via the keyboard.

### Dashboard Controls
| Key | Action | Description |
| :--- | :--- | :--- |
| **⬆️⬇️** | **Select** | Navigate through the container list. |
| **`c`** | **Create** | Create a new container. You will be prompted for a name. |
| **`r`** | **Run** | Start the selected container. You can enter a command or just hit **ENTER** to drop into a shell. |
| **`e`** | **Enter** | Open a terminal (`/bin/sh`) inside the selected container. Type `exit` to return. |
| **`s`** | **Stop** | Gracefully stop the selected container (sends SIGTERM to PID 1). |
| **`x`** | **Delete** | Remove the selected container and clean up its resources. |
| **`q`** | **Quit** | Exit the Quark runtime. |

### Examples

#### 1. Running a Python One-Liner
1.  Select a container and press `r`.
2.  Enter Command: `/usr/bin/python3 -c "print('Hello from inside Quark!')"`
3.  The output will appear on screen.

#### 2. Interactive Shell
1.  Select a container and press `r`.
2.  Leave the command blank and press **ENTER**.
3.  You are now `root` inside the container!
4.  Run `ps aux` to see that you are isolated (PID 1).
5.  Type `exit` to return to the dashboard.

---

## 🧠 Technical Architecture

Quark uses low-level Linux syscalls to create containers from scratch:

1.  **`clone(CLONE_NEWPID | ...)`**: Creates a new process with its own Namespaces. This is the heart of containerization.
2.  **`cgroups`**: Writes to `/sys/fs/cgroup` to enforce limits. For example, setting `cpu.max` limits the container's CPU cycles.
3.  **`mount --bind`**: Instead of downloading a heavy Docker image, Quark "borrows" your host's `/bin`, `/lib`, and `/usr` directories using read-only bind mounts. This makes containers instant and lightweight.
4.  **`pivot_root` / `chroot`**: Changes the root directory to `/tmp/minicontainer/rootfs`, trapping the process inside.

---

## ⚠️ Disclaimer
This project is for **educational purposes**. While it implements real isolation, it is not intended for production security. Do not run untrusted code as root, even inside a container.

---
*Built with ❤️ by [Saad H Tiwana](https://github.com/saadhtiwana)*
