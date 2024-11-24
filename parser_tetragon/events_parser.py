import subprocess
import sys
import signal
import io
import threading
import queue

def run_kubectl_command():
    # Define the command to run
    command = [
        "kubectl", "exec", "-n", "kube-system", "-ti", "daemonset/tetragon", 
        "-c", "tetragon", "--", "tetra", "getevents", "-o", "compact", 
        "--pods", "sith-infiltrator"
    ]

    # Create a queue for thread-safe communication
    output_queue = queue.Queue()
    should_stop = threading.Event()

    def reader_thread(stream, queue):
        """Thread function to continuously read from a stream"""
        for line in iter(stream.readline, ''):
            queue.put(line)
            if should_stop.is_set():
                break
        stream.close()

    # Start the subprocess with unbuffered output
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1  # Line buffered
    )

    # Start reader threads for stdout and stderr
    stdout_thread = threading.Thread(
        target=reader_thread,
        args=(process.stdout, output_queue)
    )
    stderr_thread = threading.Thread(
        target=reader_thread,
        args=(process.stderr, output_queue)
    )

    stdout_thread.daemon = True
    stderr_thread.daemon = True
    stdout_thread.start()
    stderr_thread.start()

    def cleanup():
        """Clean up function to ensure we read all remaining output"""
        should_stop.set()
        
        # Try to read any remaining output
        try:
            while not output_queue.empty():
                line = output_queue.get_nowait()
                sys.stdout.write(line)
                sys.stdout.flush()
        except queue.Empty:
            pass

        # Read any remaining output directly from the process
        remaining_output, remaining_errors = process.communicate(timeout=2)
        if remaining_output:
            sys.stdout.write(remaining_output)
            sys.stdout.flush()
        if remaining_errors:
            sys.stderr.write(f"ERROR: {remaining_errors}")
            sys.stderr.flush()

        process.terminate()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

    def handle_interrupt(signum, frame):
        print("\nInterrupted. Reading remaining logs...")
        cleanup()
        sys.exit(0)

    # Set up the interrupt handler
    signal.signal(signal.SIGINT, handle_interrupt)

    try:
        # Main loop to read and print output
        while process.poll() is None:
            try:
                # Get output from queue with timeout to allow for interrupts
                line = output_queue.get(timeout=0.1)
                sys.stdout.write(line)
                sys.stdout.flush()
            except queue.Empty:
                continue

    except Exception as e:
        print(f"\nAn error occurred: {e}")

    finally:
        cleanup()

if __name__ == "__main__":
    run_kubectl_command()