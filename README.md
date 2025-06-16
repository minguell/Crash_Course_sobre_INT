# Crash_Course_sobre_INT

## 🔧 Setup

### **Step 1: Activate the Python Environment**

The virtual machine includes a pre-configured Python environment located at:

```bash
/home/p4/src/p4dev-python-venv
```

Activate it with:

```bash
source /home/p4/src/p4dev-python-venv/bin/activate
```

### **Step 2: Compile and Run the Exercise**

Navigate to the exercise folder:

```bash
cd Crash_Course_sobre_INT/skeleton/TP-skel
```

Run the P4 compiler and launch the Mininet topology with:

```bash
make run
```

## 🖥️ Getting started

### **1. Open terminals for hosts**

From the **Mininet CLI**, you can open terminal windows for any hosts using the `xterm` command. For example, to open terminals for hosts named `h1`, `h2`, and `h3`:

```bash
xterm h1 h2 h3
```

### **2. Send and receive messages between hosts**

#### **On the receiving host:**

In the terminal of the host that should **receive** the message, run:

```bash
python3 receive.py
```

This script will listen for incoming messages.

---

#### **On the sending host:**

In the terminal of the host that should **send** the message, run:

```bash
python3 send.py <destination_ip> "<message>"
```

* Replace `<destination_ip>` with the IP address of the receiving host.
* Replace `<message>` with the text you want to send.

**Example:**

```bash
python3 send.py 10.0.2.2 "Hello from h1!"
```

---

### **3. How to find a host's IP address**

If you're unsure of the IP address of a host, you can check it from the host's terminal by running:

```bash
ip addr
```

Or from the Mininet CLI:

```bash
mininet> h2 ifconfig
```

Look for an IP address typically in the `10.0.0.x` range, depending on your topology.

### ⚠️ **Reminder:**

These steps are intended to be executed **inside the VM provided by the professor**, which has the required tools (P4 compiler, Mininet, gRPC libraries, etc.) pre-installed.
