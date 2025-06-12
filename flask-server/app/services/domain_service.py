import requests 
import time
import threading

class DomainService:

    supported_attacks = {
        "xss": "Cross-Site Scripting",
        "sql_injection": "SQL Injection",
        # Add more attack types here
    }
    
    SQLMAP_API = 'http://localhost:8775'

    @staticmethod
    def scan_domain(domain, attacks):
        results = {}

        for attack in attacks:
            if attack == "xss":
                results['xss'] = DomainService.check_xss(domain)
            elif attack == "sql_injection":
                results['sql_injection'] = DomainService.check_sql_injection(domain)
            # Add more attack types here
            else:
                results[attack] = "Unknown attack type"

        return {
            "domain": domain,
            "results": results
        }

    # Define methods for checking vulnerabilities over here
    @staticmethod
    def check_xss(domain):
        # Mock logic for XSS vulnerability
        return "No XSS vulnerability found"

    @staticmethod
    def check_sql_injection(domain):
        """SQL injection check using SQLMap"""
        try:
     
            task_res = requests.get(f'{DomainService.SQLMAP_API}/task/new')
            task_data = task_res.json()
            task_id = task_data.get('taskid')
            
            if not task_id:
                return {'error': 'Failed to create new task', 'status': 'error'}
            
   
            options_payload = {
                'options': {
                    'url': domain,
                    'batch': True,
                    'crawl': 3,
                    'randomAgent': True,
                    'threads': 5,
                    'risk': 2
                }
            }
            
            requests.post(f'{DomainService.SQLMAP_API}/option/{task_id}/set', json=options_payload)
            

            scan_payload = {'url': domain}
            requests.post(f'{DomainService.SQLMAP_API}/scan/{task_id}/start', json=scan_payload)
            

            thread = threading.Thread(target=DomainService._check_scan_status, args=(task_id,))
            thread.daemon = True
            thread.start()
            
       
            time.sleep(10)
            

            status_res = requests.get(f'{DomainService.SQLMAP_API}/scan/{task_id}/status')
            status_data = status_res.json()
            is_terminated = status_data.get('status') == 'terminated'
            
            if not is_terminated:
                return {
                    'status': 'running',
                    'message': 'Scan still in progress, try again later',
                    'task_id': task_id
                }
            
        
            log_res = requests.get(f'{DomainService.SQLMAP_API}/scan/{task_id}/log')
            log_data = log_res.json()
            log_entries = log_data.get('log', [])
            
            if not log_entries:
                return {
                    'status': 'completed',
                    'message': 'No log data found.'
                }
            
            
            full_log = ' '.join(entry.get('message', '') for entry in log_entries)
            words = full_log.strip().split()
            last_1000_words = ' '.join(words[-1000:])
            
            if "no parameter(s) found for testing" in last_1000_words:
                result = "NO VULNERABILITIES FOUND"
            else:
                result = "THERE ARE VULNERABILITIES"
            
            return {
                'status': 'completed',
                'result': result,
                'response': last_1000_words,
                'task_id': task_id
            }
            
        except requests.exceptions.RequestException as e:
            print(f"Request error: {e}")
            return {'error': f'Request error: {str(e)}', 'status': 'error'}
        except Exception as e:
            print(f"Unexpected error: {e}")
            return {'error': f'Unexpected error: {str(e)}', 'status': 'error'}

    @staticmethod
    def _check_scan_status(task_id, delay=10):
        """Background function to check scan status after delay"""
        time.sleep(delay)
        
        try:
            
            status_res = requests.get(f'{DomainService.SQLMAP_API}/scan/{task_id}/status')
            status_data = status_res.json()
            is_terminated = status_data.get('status') == 'terminated'
            
            if not is_terminated:
                print(f"Scan {task_id} still running")
                return
            
            
            log_res = requests.get(f'{DomainService.SQLMAP_API}/scan/{task_id}/log')
            log_data = log_res.json()
            log_entries = log_data.get('log', [])
            
            if not log_entries:
                print(f"Scan {task_id} completed - No log data found")
                return
            
      
            full_log = ' '.join(entry.get('message', '') for entry in log_entries)
            words = full_log.strip().split()
            last_1000_words = ' '.join(words[-1000:])
            
            if "no parameter(s) found for testing" in last_1000_words:
                print("NO VULNERABILITIES FOUND")
            else:
                print("THERE ARE VULNERABILITIES")
              
            print(f"Scan {task_id} completed successfully")
            
        except Exception as e:
            print(f"Error checking scan status: {e}")
    
    @classmethod
    def get_supported_attacks(cls):
        return cls.supported_attacks