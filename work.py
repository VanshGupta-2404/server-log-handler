import re
import csv
from collections import defaultdict, Counter


logfile = "final.log"
csvfile = "log_analysis_results.csv"
failed_occurence = 10

def parsefile(log_file):

    with open(log_file, 'r') as file:
        logs = file.readlines()

    data = []
    for line in logs:
        match = re.match(r'(?P<ip>\S+) .* "(?P<method>\S+) (?P<endpoint>\S+).*" (?P<status>\d+)', line)
        if match:
            data.append(match.groupdict())
    return data

def countrequest(data):
    
    ipcou = Counter([entry['ip'] for entry in data])
    return ipcou

def findmostoccur(data):
   
    endpoint_counter = Counter([entry['endpoint'] for entry in data])
    most_common = endpoint_counter.most_common(1)
    return most_common[0] if most_common else None

def detect_suspicious_activity(data):
    
    failed_attempts = defaultdict(int)
    for entry in data:
        if entry['status'] == '401':
            failed_attempts[entry['ip']] += 1

    suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count > failed_occurence}
    return suspicious_ips

def csvsave(ip_counts, most_accessed_endpoint, suspicious_ips):
    
    with open(csvfile, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])

   
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        if most_accessed_endpoint:
            writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])


        writer.writerow([])
        writer.writerow(["Suspicious IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

if __name__ == "__main__":

    log_data = parsefile(logfile)

  
    ip_counts = countrequest(log_data)
    most_accessed_endpoint = findmostoccur(log_data)
    suspicious_ips = detect_suspicious_activity(log_data)

  
    print("Requests per IP Address:")
    for ip, count in ip_counts.most_common():
        print(f"{ip:<20} {count}")

    if most_accessed_endpoint:
        print("\nMost Frequently Accessed Endpoint:")
        print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")


    csvsave(ip_counts, most_accessed_endpoint, suspicious_ips)
    print(f"\nResults saved to {csvfile}")
