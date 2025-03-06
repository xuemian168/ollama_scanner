import requests
import concurrent.futures
import socket
from typing import List, Dict, Union, Optional
import ipaddress
from tqdm import tqdm

class OllamaScan:
    def __init__(self):
        self.port = 11434
        self.timeout = 3

    def chat_with_model(self, ip: str, model_name: str, message: str) -> Dict:
        """与指定模型进行对话"""
        try:
            payload = {
                "model": model_name,
                "messages": [
                    {
                        "role": "user",
                        "content": message
                    }
                ],
                "stream": True
            }
            
            response = requests.post(
                f"http://{ip}:{self.port}/api/chat",
                json=payload,
                timeout=(3, 30),
                stream=True
            )
            response.raise_for_status()
            
            import json
            
            print("\n模型回复:", end="", flush=True)
            full_response = ""
            for line in response.iter_lines():
                if line:
                    try:
                        chunk = line.decode('utf-8')
                        chunk_data = json.loads(chunk) 
                        if 'message' in chunk_data:
                            content = chunk_data['message'].get('content', '')
                            print(content, end="", flush=True)
                            full_response += content
                    except Exception as e:
                        print(f"\n解析响应出错: {e}")
            print()
            
            return {'message': {'content': full_response}}
            
        except requests.Timeout:
            return {'error': 'Timeout'}
        except requests.ConnectionError:
            return {'error': 'Connect Failed'}
        except requests.RequestException as e:
            return {'error': f'Chat failed: {str(e)}'}

    def verify_ollama(self, ip: str) -> Dict[str, Union[bool, str, Dict]]:
        """验证是否为Ollama服务"""
        try:
            session = requests.Session()
            retries = requests.adapters.Retry(
                total=3,  # 总重试次数
                backoff_factor=0.5,  # 重试间隔
                status_forcelist=[500, 502, 503, 504],  # 需要重试的HTTP状态码
                allowed_methods=["GET"]  # 允许重试的请求方法
            )
            session.mount('http://', requests.adapters.HTTPAdapter(max_retries=retries))
            
            # 首先验证根路径
            root_response = session.get(
                f"http://{ip}:{self.port}", 
                timeout=(5, 10),  # (连接超时, 读取超时)
                headers={'Connection': 'close'}  # 避免连接复用
            )
            if "Ollama is running" not in root_response.text:
                return {'is_ollama': False, 'reason': 'Not an Ollama service'}

            # 获取模型信息
            tags_response = session.get(
                f"http://{ip}:{self.port}/api/tags",
                timeout=(5, 10),
                headers={'Connection': 'close'}
            )
            if tags_response.status_code != 200:
                return {'is_ollama': True, 'reason': 'Unable to get model information'}

            models_data = tags_response.json()
            return {
                'is_ollama': True,
                'models': [{
                    'name': model.get('name', ''),
                    'size': model.get('size', 0),
                    'digest': model.get('digest', ''),
                    'modified_at': model.get('modified_at', ''),
                    'details': model.get('details', {})
                } for model in models_data.get('models', [])]
            }

        except requests.Timeout:
            return {'is_ollama': False, 'reason': f'Connection timed out'}
        except requests.ConnectionError:
            return {'is_ollama': False, 'reason': f'Connect failed'}
        except requests.RequestException as e:
            return {'is_ollama': False, 'reason': f'Error: {str(e)}'}

    def scan_single_ip(self, ip: str) -> Optional[Dict]:
        """扫描单个IP"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                if s.connect_ex((ip, self.port)) == 0:
                    result = self.verify_ollama(ip)
                    return {
                        'ip': ip,
                        'port_open': True,
                        **result
                    }
        except Exception as e:
            return {
                'ip': ip,
                'port_open': False,
                'error': str(e)
            }
        return None

    def scan_network(self, network: str) -> List[Dict]:
        """扫描网段"""
        try:
            network = ipaddress.IPv4Network(network)
        except ValueError:
            # 如果不是有效的网段，尝试作为单个IP处理
            try:
                ipaddress.IPv4Address(network)
                result = self.scan_single_ip(network)
                return [result] if result else []
            except ValueError:
                raise ValueError("无效的IP地址或网段")

        results = []
        hosts = list(network.hosts())
        total_hosts = len(hosts)
        
        if total_hosts > 1:  # 只有扫描网段时才显示进度条
            with tqdm(total=total_hosts, desc="Scanning Progress", unit="ip") as pbar:
                with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                    future_to_ip = {
                        executor.submit(self.scan_single_ip, str(ip)): str(ip)
                        for ip in hosts
                    }
                    
                    for future in concurrent.futures.as_completed(future_to_ip):
                        result = future.result()
                        if result:
                            results.append(result)
                        pbar.update(1)
        else:
            # 单个IP直接扫描
            result = self.scan_single_ip(str(hosts[0]))
            if result:
                results.append(result)
        
        return results

def main():
    scanner = OllamaScan()
    
    while True:
        target = input("Enter IP address or network range (e.g., 192.168.1.1 or 192.168.1.0/24): ").strip()
        if not target:
            break
            
        try:
            results = scanner.scan_network(target)
            
            print("\nScanning Results:")
            for result in results:
                print(f"\nIP: {result['ip']}")
                print(f"Port Status: {'Open' if result['port_open'] else 'Closed'}")
                
                if result.get('is_ollama'):
                    print("Ollama Service: Running")
                    if 'models' in result:
                        print("Installed Models:")
                        for model in result['models']:
                            print(f"  - {model['name']}")
                            print(f"    Size: {model['size']} bytes")
                            print(f"    Digest: {model['digest']}")
                            if model.get('details'):
                                print(f"    Parameter Size: {model['details'].get('parameter_size', 'N/A')}")
                                print(f"    Quantization Level: {model['details'].get('quantization_level', 'N/A')}")
                        
                        if result['models']:
                            while True:
                                chat_choice = input("\nChat with model? (y/n): ").strip().lower()
                                if chat_choice != 'y':
                                    break
                                    
                                print("\nAvailable Models:")
                                for idx, model in enumerate(result['models'], 1):
                                    print(f"{idx}. {model['name']}")
                                
                                try:
                                    model_idx = int(input("Select model number: ")) - 1
                                    if 0 <= model_idx < len(result['models']):
                                        message = input("Enter your message: ")
                                        chat_result = scanner.chat_with_model(
                                            result['ip'],
                                            result['models'][model_idx]['name'],
                                            message
                                        )
                                        
                                        if 'error' in chat_result:
                                            print(f"Error: {chat_result['error']}")
                                        else:
                                            print("\nModel Response:")
                                            print(chat_result.get('message', {}).get('content', 'No response'))
                                    else:
                                        print("Invalid model number")
                                except (ValueError, IndexError):
                                    print("Invalid input")
                                except Exception as e:
                                    print(f"Chat error: {e}")
                                
                elif 'reason' in result:
                    print(f"Status: {result['reason']}")
                
                if 'error' in result:
                    print(f"Error: {result['error']}")
                    
        except ValueError as e:
            print(f"Error: {e}")
        except Exception as e:
            print(f"Scan error: {e}")
        
        print("\nPress Enter to continue scanning, or Enter directly to exit")

if __name__ == "__main__":
    main()
