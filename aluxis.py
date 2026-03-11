import socket
import threading
from queue import Queue
import time
import csv
import os
import sys
import argparse

protocols = {}

max_threads = 500
target = "127.0.0.1"
print_lock = threading.Lock() 
q = Queue() 

def load_assets(filename="assets_top1000.csv"):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, filename)
    
    try:
        with open(file_path, mode='r') as file:
            reader = csv.reader(file)
            for row in reader:
                if len(row) >= 2:
                    port = int(row[0].strip())
                    service = row[1].strip()
                    risk = row[2].strip() if len(row) > 2 else "UNKNOWN"
                    #store structured data
                    protocols[port] = {"service": service, "risk": risk}
    except FileNotFoundError:
        print(f"[FATAL] Asset file {file_path} not found. Halting operations.")
        sys.exit(1)
        
def port_scan(port, target):
    #single port scan for the single thread
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #time lost to skip to the next port if doesn't respond
    s.settimeout(1) 
    
    try:
        result = s.connect_ex((target, port))
        #block the console for avoiding the mix of logs
        with print_lock:
            if result == 0:
                asset_info = protocols.get(port, {})
                svc = asset_info.get("service", "UNKNOWN")
                risk = asset_info.get("risk", "UNKNOWN")
                print(f"[!] {target}:{port}/TCP | SVC: {svc} | RISK: {risk} | STATUS: EXPOSED")
    except Exception:
        pass 
    finally:
        s.close() 
        
def worker(target):
    #loop to get the port list
    while True:
        port = q.get()
        port_scan(port, target)
        q.task_done() 

def main():
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("-t", "--target", required=True, help="Target IP address (e.g., 192.168.1.1)")
    args = parser.parse_args()
    
    target_ip = args.target
    start_time = time.time()
    print(f"--- [ALUXIS] NIS2 Audit Init: {target_ip} ---")
    
    load_assets()
    
    #dynamic thread allocation based on the asset volume
    num_threads = min(len(protocols), max_threads)
    
    for _ in range(num_threads):
        t = threading.Thread(target=worker, args=(target_ip,))
        t.daemon = True #threads will die when completed
        t.start()

    for port in protocols.keys():
        q.put(port)

    q.join() #wait for threads to finish
    
    execution_time = time.time() - start_time
    print(f"--- Audit Completed in {execution_time:.4f} seconds ---")

if __name__ == "__main__":
    main()