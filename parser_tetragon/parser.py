import subprocess
import json

def parse_logs():
    # Command to get logs dynamically
    command = [
        "kubectl", "logs", "-n", "kube-system",
        "-l", "app.kubernetes.io/name=tetragon",
        "-c", "export-stdout", "-f"
    ]
    
    try:
        # Run the command and read stdout line by line
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        print("Parsing logs (Press CTRL+C to stop)...")
        
        for line in process.stdout:
            try:
                # Attempt to parse the line as JSON
                log_entry = json.loads(line)
                
                # Extract the nested "process_exec.process" object if it exists
                process_exec = log_entry.get("process_exec", {})
                process_data = process_exec.get("process", {})
                
                # Extract relevant fields from the process data
                pid = process_data.get("pid")
                cwd = process_data.get("cwd")
                binary = process_data.get("binary")
                arguments = process_data.get("arguments")
                
                # Only print if all fields are present
                if all([pid, cwd, binary, arguments]):
                    print(f"PID: {pid}, CWD: {cwd}, Binary: {binary}, Arguments: {arguments}")
            
            except json.JSONDecodeError:
                # If the line is not JSON, skip it
                print("Warning: Non-JSON line encountered, skipping.")
                continue
            
    except KeyboardInterrupt:
        # Handle CTRL+C gracefully
        print("\nStopped log parsing.")
    finally:
        process.terminate()

if __name__ == "__main__":
    parse_logs()
