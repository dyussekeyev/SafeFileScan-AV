import hashlib
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

def parse_log(filename, hash_sha256):
    command = 'kesl-control -E --query "EventType==\'ThreatDetected\'"'
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {result.stderr}")

    pattern = re.compile(
        r"EventType=ThreatDetected.*?"
        r".*?FileName=(.*?)\s"
        r".*?DetectName=(.*?)\s"
        r".*?Sha256Hash=(.*?)\s",
        re.DOTALL
    )

    matches = pattern.findall(result.stdout)
    parsed_data = []

    for match in matches:
        if match[0] == file_name and match[2] == hash_sha256:
            entry = {
                'FileName': match[0],
                'DetectName': match[1],
                'Sha256Hash': match[2]
            }
            parsed_data.append(entry)

    return parsed_data[-1] if parsed_data else None

def put_scan(api_key, base_url, scan_id, verdict, hash_value):
    response = requests.post(f"{base_url}/api/put_scan.php", json={"api_key": api_key, "scan_id": scan_id, "verdict": verdict, "hash_value": hash_value})
    response.raise_for_status()
    return response.json()

def calculate_sha256(file_content):
    sha256 = hashlib.sha256()
    sha256.update(file_content)
    return sha256.hexdigest()

def main():
    base_url = "http://127.0.0.1/"
    api_key = "dummykey"
    
    try:
        # Get list of IDs
        scans = get_scans(api_key, base_url)
        for scan in scans["scans"]:
            scan_id = scan
            
            # Download file
            file_content = get_file(api_key, base_url, scan_id)

            # Calculate size and sha256
            file_size = len(file_content)
            hash_sha256 = calculate_hashes(file_content)

            # Save file
            temp_file = save_to_temp_file(file_content)

            # Scan file
            stdout, stderr = scan_file(temp_file_path)

            # Parse results
            results = parse_log(temp_file_path, hash_sha256)

            # Send result
            put_scan(api_key, base_url, scan_id, results['DetectName'], results['DetectName'])
            print(f"Processed file ID {scan_id} with verdict {results['DetectName']} bytes and sha256 {results['Sha256Hash']}.")
    
    except requests.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except Exception as err:
        print(f"An error occurred: {err}")

if __name__ == "__main__":
    main()
