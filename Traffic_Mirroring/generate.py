import subprocess
import random
import threading
import time

class WindowsPingTrafficGenerator:
    def __init__(self, vm_ip: str):
        """
        Initialize Ping Traffic Generator for Windows
        
        :param vm_ip: IP address of the Ubuntu VM
        """
        self.vm_ip = vm_ip
    
    def generate_ping_traffic(self, duration: int = 60, packet_size: int = 64):
        """
        Generate continuous ping traffic to VM from Windows
        
        :param duration: Total traffic generation duration
        :param packet_size: Size of ping packets in bytes
        """
        try:
            start_time = time.time()
            
            while time.time() - start_time < duration:
                try:
                    # Windows ping command parameters
                    # -n 1: Send only one packet
                    # -l: Set packet size
                    # -w 1000: Timeout of 1 second (1000 ms)
                    ping_command = [
                        'ping', 
                        '-n', '1',      # Number of echo requests
                        '-l', str(packet_size),  # Packet size
                        '-w', '1000',   # Timeout in milliseconds
                        self.vm_ip
                    ]
                    
                    # Execute ping using subprocess
                    result = subprocess.run(
                        ping_command, 
                        capture_output=True, 
                        text=True, 
                        shell=True
                    )
                    
                    # Print ping result
                    print(f"Ping to {self.vm_ip} at {time.ctime()}:")
                    print(result.stdout)
                    
                    # Random interval between pings
                    time.sleep(random.uniform(0.1, 0.5))
                
                except Exception as e:
                    print(f"Ping error: {e}")
                    break
        
        except Exception as e:
            print(f"Ping traffic generation error: {e}")
    
    def simulate_ping_traffic(self, total_duration: int = 60, concurrent_streams: int = 3):
        """
        Simulate concurrent ping traffic streams
        
        :param total_duration: Total traffic generation duration
        :param concurrent_streams: Number of concurrent ping streams
        """
        threads = []
        
        for i in range(concurrent_streams):
            # Vary packet sizes for different streams
            packet_size = random.randint(128, 512)
            
            thread = threading.Thread(
                target=self.generate_ping_traffic, 
                args=(total_duration, packet_size)
            )
            
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()

def main():
    # REPLACE with your Ubuntu VM's actual IP address
    VM_IP = '192.168.68.129'  # Example IP - modify this!
    
    generator = WindowsPingTrafficGenerator(VM_IP)
    print(f"Starting ping traffic simulation to {VM_IP}...")
    generator.simulate_ping_traffic(total_duration=120, concurrent_streams=15)
    print("Ping traffic simulation completed.")

if __name__ == "__main__":
    main()
