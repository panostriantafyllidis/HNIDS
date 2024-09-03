import signal
import time

import matplotlib.pyplot as plt
import psutil

# Lists to store time, CPU, and memory usage
time_points = []
cpu_usage = []
memory_usage = []

# Define a flag to indicate whether monitoring should continue
monitoring = True


# Define the signal handler for graceful termination
def signal_handler(sig, frame):
    global monitoring
    print("\nStopping monitoring...")
    monitoring = False


# Register the signal handler
signal.signal(signal.SIGINT, signal_handler)

# Start time
start_time = time.time()

# Real-time monitoring loop
while monitoring:
    try:
        # Get current CPU and memory usage
        cpu = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory().percent

        # Append to lists
        elapsed_time = time.time() - start_time
        time_points.append(elapsed_time)
        cpu_usage.append(cpu)
        memory_usage.append(memory)

        # Print the progress
        print(f"Time: {elapsed_time:.2f}s, CPU: {cpu}%, Memory: {memory}%")

        # Plot in real-time
        plt.clf()
        plt.subplot(2, 1, 1)
        plt.plot(time_points, cpu_usage, label="CPU Usage (%)", color="blue")
        plt.xlabel("Time (s)")
        plt.ylabel("CPU Usage (%)")
        plt.title("CPU Usage Over Time")
        plt.legend()
        plt.grid(True)

        plt.subplot(2, 1, 2)
        plt.plot(time_points, memory_usage, label="Memory Usage (%)", color="red")
        plt.xlabel("Time (s)")
        plt.ylabel("Memory Usage (%)")
        plt.title("Memory Usage Over Time")
        plt.legend()
        plt.grid(True)

        # Adjust the layout to add more space between subplots
        plt.subplots_adjust(hspace=0.5)  # Increase hspace value to add more space

        plt.pause(0.1)

    except KeyboardInterrupt:
        # Handle Ctrl-C manually (optional, since signal already handles it)
        break

# Save the plot as a PNG file
plt.savefig("cpu_memory_usage.png")
print("Plot saved as 'cpu_memory_usage.png'")

# Finalize the plot after monitoring is stopped
plt.tight_layout()
plt.show()
