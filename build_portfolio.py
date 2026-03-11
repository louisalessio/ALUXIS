import urllib.request
import csv
import os

NMAP_SERVICES_URL = "https://raw.githubusercontent.com/nmap/nmap/master/nmap-services"

def probability():
    try:
        response = urllib.request.urlopen(NMAP_SERVICES_URL)
        lines = response.read().decode('utf-8').splitlines()
    except Exception as e:
        print(f"ERROR retrieving data: {e}")
        return []

    assets = []
    for line in lines:
        if line.startswith('#') or not line.strip(): 
            continue
            
        parts = line.split()
        #only TCP
        if len(parts) >= 3 and '/tcp' in parts[1]:
            service = parts[0]
            port = int(parts[1].split('/')[0])
            frequency = float(parts[2]) 
            assets.append((port, service, frequency))
    
    #sort from the most likely to be used
    assets.sort(key=lambda x: x[2], reverse=True)
    #cut more than the first 1000 results
    return assets[:1000]

def createCSV(assets, filename="assets_top1000.csv"):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, filename)
    #data to csv
    with open(file_path, 'w', newline='') as f:
        writer = csv.writer(f)
        for port, service, frequency in assets:
            writer.writerow([port, service, "TARGET"])
            
    print("csv populated with the 1000 most popular ports DONE")

if __name__ == "__main__":
    top_1000_assets = probability()
    if top_1000_assets:
        createCSV(top_1000_assets)