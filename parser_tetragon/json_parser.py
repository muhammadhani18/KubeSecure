import re
import subprocess
import sys
import signal
import threading
import queue
import json
import datetime
 
def run_kubectl_command(pod_name):
    # Define the command to run
    command = [
        "kubectl", "exec", "-n", "kube-system", "-ti", "daemonset/tetragon", 
        "-c", "tetragon", "--", "tetra", "getevents", "-o", "compact", 
        "--pods", "sith-infiltrator"
    ]

    # Create a queue for thread-safe communication
    output_queue = queue.Queue()
    should_stop = threading.Event()

    # File to store events
    json_file = "events.json"

    # Initialize the JSON file with an empty array if it doesn't already exist
    with open(json_file, "w") as f:
        json.dump([], f, indent=4)

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
    
    def clean_ansi_escape(text):
        """Remove ANSI escape codes from a string"""
        ansi_escape_pattern = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape_pattern.sub('', text).strip()

    def parse_log_line(line):
        """Parse a log line into a clean JSON object"""
        # Remove emojis and split log components
        components = line.replace("ðŸš€", "").replace("ðŸ›‘", "").strip().split()
        if len(components) < 3:
            return None

        # Clean and extract relevant fields
        command_string = " ".join(components[2:-1])
        capabilities = components[-1]

        return {
            "event": "process",
            "timestamp": datetime.datetime.now().isoformat(),  # Add timestamp
            "pod": pod_name,
            "command": clean_ansi_escape(command_string),
            "capabilities": clean_ansi_escape(capabilities)
        }

    def append_to_file(data, file_path):
        """Append a new JSON object to the existing JSON array in a file"""
        try:
            with open(file_path, "r+") as f:
                existing_data = json.load(f)
                existing_data.append(data)
                f.seek(0)  # Move to the start of the file
                json.dump(existing_data, f, indent=4)
        except Exception as e:
            print(f"Error while appending to file: {e}")

    def cleanup():
        """Clean up function to ensure we read all remaining output"""
        should_stop.set()
        
        # Read any remaining output directly from the process
        remaining_output, remaining_errors = process.communicate(timeout=2)
        if remaining_output:
            for line in remaining_output.splitlines():
                parsed_event = parse_log_line(line)
                if parsed_event:
                    append_to_file(parsed_event, json_file)
        if remaining_errors:
            sys.stderr.write(f"ERROR: {remaining_errors}\n")
            sys.stderr.flush()

        process.terminate()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

    def handle_interrupt(signum, frame):
        print("\nInterrupted. Cleaning up...")
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

                # Parse the line and save directly to the file
                parsed_event = parse_log_line(line)
                if parsed_event:
                    append_to_file(parsed_event, json_file)

            except queue.Empty:
                continue

    except Exception as e:
        print(f"\nAn error occurred: {e}")

    finally:
        print("\nCleaning up...")
        cleanup()

if __name__ == "__main__":
    run_kubectl_command("sith-infiltrator")
