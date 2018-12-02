import time
import json
import hashlib
import requests
import collections

# Function to return sha256 hash of a filename
def sha256_checksum(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()

# API Call
# 4 requests per minute :(
def api_call(proc_names):

# Should return list of file name and state {Good, BAD, Unsure}
    
    
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    # files = []
    # Example files
    # files.append("C:\Program Files\Greenshot\Greenshot12.exe")
    # files.append("C:\Windows\System32\svchost.exe")

    # List to keep track of report
    # Report in the format of [indicator, filename] where indicator is 0, 1, 2
    # 0 = Safe, 1 =  Malicious, 2 = Unsure, 3 = unknown
    count = 0

    for process in proc_names:


        for x in range(0, len(process.filePaths)):
            
            try:
                params = {'apikey': '9166fb790fba6b3ffb5d245c906e1e9538a8862c91d7a5f3311eb33d25c70c1e', 'resource': sha256_checksum(process.filePaths[x]), 'allinfo': False}

                response = requests.get(url, params=params)
                count += 1
                if count == 4:
                     time.sleep(60)
                     count = 0

                data = json.loads(response.text)
                positives = data['positives']

            # Unsure
                if positives > 0 and positives < 5:
                    print(str(2) + ": " + process.filePaths[x])
                    process.status = 2
                    
                    
            # Malicious
                if positives > 5:
                    # print(str(1) + ": " + process.filePaths[x])
                    print(process.filePaths[x] + ": malicious")
                    process.status = 1
                    break
                    

            # Safe
                if positives == 0:
                    # print(str(0) + ": " + process.filePaths[x])
                    print(process.filePaths[x] + ": safe")
                    process.status = 0
                    

            except:
                print(print(str(3) + ": " + process.filePaths[x]))
                process.status = 3
                

    return proc_names  