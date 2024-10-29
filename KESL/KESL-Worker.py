import re
import requests
import subprocess
import tempfile

def get_scans(api_key, base_url):
    response = requests.post(f"{base_url}/api/get_scans.php", json={"api_key": api_key})
    response.raise_for_status()
    return response.json

def get_file(api_key, base_url, scan_id):
    response = requests.post(f"{base_url}/api/get_file.php", json={"api_key": api_key, "scan_id": scan_id})
    response.raise_for_status()
    return response.content

def save_to_temp_file(content):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".tmp") as temp_file:
        temp_file.write(content)
        temp_file_path = temp_file.name
    return temp_file_path

def scan_file(filename):
    command = f"kesl-control --scan-file {filename} --action Skip"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout, result.stderr

def parse_log():
    command = 'kesl-control -E --query "EventType==\'ThreatDetected\'"'
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {result.stderr}")

    pattern = re.compile(
        r"Date=(.*?)\s"
        r".*?FileName=(.*?)\s"
        r".*?DetectName=(.*?)\s"
        r".*?Md5Hash=(.*?)\s"
        r".*?Sha256Hash=(.*?)\s"
    )

    matches = pattern.findall(result.stdout)
    parsed_data = []

    for match in matches:
        entry = {
            'Date': match[0],
            'FileName': match[1],
            'DetectName': match[2],
            'Md5Hash': match[3],
            'Sha256Hash': match[4]
        }
        parsed_data.append(entry)

    return parsed_data

def put_scan(api_key, base_url, scan_id, verdict, sha1):
    response = requests.post(f"{base_url}/api/put_scan.php", json={"api_key": api_key, "scan_id": scan_id, "verdict": verdict, "sha1": sha1})
    response.raise_for_status()
    return response.json()

def main():
    base_url = "http://127.0.0.1/"
    api_key = "keslkey"
    
    try:
        # Get list of IDs
        scans = get_scans(api_key, base_url)
        for scan in scans["scans"]:
            scan_id = scan
            
            # Download file
            file_content = get_file(api_key, base_url, scan_id)
            file_size = len(file_content)
            temp_file = save_to_temp_file(file_content)

            # Scan file
            stdout, stderr = scan_file(temp_file_path)

            # Parse results
            results = parse_log()
            print(results)

            # Send result
            #verdict = f"Dummy result - {file_size}"
            #put_scan(api_key, base_url, scan_id, results[''], sha1)
            #print(f"Processed file ID {scan_id} with size {file_size} bytes and sha1 {sha1}.")
    
    except requests.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except Exception as err:
        print(f"An error occurred: {err}")

if __name__ == "__main__":
    main()
