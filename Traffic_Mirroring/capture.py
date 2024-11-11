import os
import pandas as pd
import time
import signal
import subprocess

def run_cicflowmeter():
    # Start the cicflowmeter command in a subprocess
    process = subprocess.Popen(["sudo", "cicflowmeter", "-i", "ens33", "-c", "flows.csv"])
    return process

def stop_cicflowmeter(process):
    # Terminate the process
    process.send_signal(signal.SIGINT)  # Sends interrupt signal to gracefully stop

def read_and_print_csv(file_path="flows.csv"):
    try:
        # Read the CSV into a pandas DataFrame
        df = pd.read_csv(file_path)
        print(df)
    except Exception as e:
        print(f"Error reading CSV file: {e}")

def main():
    while True:
        # Start cicflowmeter
        process = run_cicflowmeter()
        
        # Let it capture traffic for 3 seconds
        time.sleep(3)
        
        # Stop the cicflowmeter process
        stop_cicflowmeter(process)
        
        # Give a small delay to ensure the file is fully written
        time.sleep(1)
        
        # Read and print the DataFrame from flows.csv
        read_and_print_csv("flows.csv")

# Run the main function
if __name__ == "__main__":
    main()
