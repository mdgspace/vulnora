import requests

test_files = {

    "open_calc.py": (
    "open_calc.py",
    """import os
       os.system('calc.exe')
    """,
    "text/x-python"
    ),
    
}



def check_file_upload(domain, upload_endpoint):
    url = domain.rstrip('/') + upload_endpoint
    results = []

    for test_file, (filename, content, mime) in test_files.items():
        files = {"file": (filename, content, mime)}

        try:
            response = requests.post(url, files = files, timeout=7)

            if response.status_code == 200:
                test_url = f"{url.rstrip('/')}/uploads/{filename}"
                upload_status = file_access(test_url)
                results.append(f"{filename} Accessibility Status: {upload_status}")

            else:
                results.append(f"{filename} File Upload Failed with StatusCode = {response.status_code}")    

        except requests.exceptions.RequestException as e:
            results.append(f"[{filename}] Error during upload: {str(e)}")

    return (results)

    

def file_access(url):
    try:
        response = requests.get(url, timeout=7)
        if response.status_code == 200 :
            return f"Yes:{response.status_code}"
        
        else:
            return f"No:{response.status_code}"
        
    except requests.exceptions.RequestException as e:
        return f"Error accessing file: {str(e)}"    