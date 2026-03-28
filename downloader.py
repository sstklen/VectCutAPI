import os
import re
import subprocess
import time
import requests
import shutil
import ipaddress
from requests.exceptions import RequestException, Timeout
from urllib.parse import urlparse, unquote


# ============================================================
# [WASHIN-SECURITY] 安全驗證工具集
# ============================================================

def _safe_material_name(material_name: str) -> str:
    """防止路徑穿越攻擊：移除 .. 和絕對路徑"""
    if not material_name:
        raise ValueError("[WASHIN-SECURITY] material_name 不可為空")
    if '..' in material_name:
        raise ValueError(f"[WASHIN-SECURITY] material_name 包含 '..'，疑似路徑穿越攻擊: {material_name}")
    if material_name.startswith('/') or material_name.startswith('\\'):
        raise ValueError(f"[WASHIN-SECURITY] material_name 不可為絕對路徑: {material_name}")
    return os.path.basename(material_name)


def _safe_draft_id(draft_id: str) -> str:
    """驗證 draft_id 格式，防止路徑穿越刪除任意目錄"""
    if not draft_id:
        raise ValueError("draft_id 不可為空")
    if len(draft_id) > 128:
        raise ValueError(f"draft_id 超長（{len(draft_id)} 字元，上限 128）")
    if '..' in draft_id or '/' in draft_id or '\\' in draft_id:
        raise ValueError(f"draft_id 含非法字元: {draft_id}")
    # ASCII only：字母、數字、底線、連字號（排除 Unicode 字母）
    if not re.match(r'^[a-zA-Z0-9_\-]+$', draft_id):
        raise ValueError(f"draft_id 格式不合法: {draft_id}")
    return draft_id


def _safe_draft_folder(draft_folder: str) -> str:
    """驗證 draft_folder 不含路徑穿越，且解析後在安全範圍內"""
    if not draft_folder:
        return draft_folder
    if '..' in draft_folder:
        raise ValueError(f"draft_folder 不可包含 '..': {draft_folder}")
    resolved = os.path.realpath(draft_folder)
    # symlink 解析後必須仍在 /Users/ 或 /tmp/ 下（防 symlink 逃逸）
    ALLOWED_PREFIXES = ('/Users/', '/tmp/', '/home/')
    if not any(resolved.startswith(p) for p in ALLOWED_PREFIXES):
        raise ValueError(f"draft_folder 解析後超出安全範圍: {resolved}")
    return resolved


def _resolve_and_check_ip(hostname: str, port: int = 443) -> None:
    """對域名做 DNS 預解析，檢查實際 IP 是否為內網（防 DNS rebinding）"""
    import socket
    try:
        addrinfos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
        for family, type_, proto, canonname, sockaddr in addrinfos:
            ip = ipaddress.ip_address(sockaddr[0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                raise ValueError(f"域名 {hostname} 解析到內網地址 {ip}")
    except socket.gaierror:
        pass  # DNS 解析失敗，後續 ffmpeg/requests 也會失敗


def _validate_url(url: str) -> str:
    """驗證 URL 安全性：禁止內網、敏感路徑、非 http(s) 協定、DNS rebinding"""
    if not url:
        raise ValueError("URL 不可為空")

    # 本地檔案路徑
    if os.path.isfile(url):
        sensitive = ['.ssh', '.env', '.gnupg', 'passwd', '.aws', 'shadow',
                     '.config/claude', '.config/gh', 'id_rsa', 'credentials',
                     '.bash_history', '.zsh_history', '.gitconfig']
        for s in sensitive:
            if s in url.lower():
                raise ValueError(f"禁止存取敏感路徑: {url}")
        return url

    # 只允許 http / https
    if not url.startswith(('http://', 'https://')):
        raise ValueError(f"只允許 http/https 協定: {url}")

    parsed = urlparse(url)
    hostname = parsed.hostname or ''

    if hostname in ('localhost', ''):
        raise ValueError(f"禁止存取 localhost: {url}")

    # IP 位址直接檢查
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        # 域名：做 DNS 預解析防 rebinding
        _resolve_and_check_ip(hostname, parsed.port or 443)
    else:
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise ValueError(f"禁止存取內網/保留地址: {url}")

    return url


def download_video(video_url, draft_name, material_name):
    """
    Download video to specified directory
    :param video_url: Video URL
    :param draft_name: Draft name
    :param material_name: Material name
    :return: Local video path
    """
    # 先驗證再建目錄，避免惡意 material_name 造成副作用
    material_name = _safe_material_name(material_name)
    video_url = _validate_url(video_url)

    video_dir = f"{draft_name}/assets/video"
    os.makedirs(video_dir, exist_ok=True)
    local_path = f"{video_dir}/{material_name}"

    # Check if file already exists
    if os.path.exists(local_path):
        print(f"Video file already exists: {local_path}")
        return local_path

    try:
        # Use ffmpeg to download video
        command = [
            'ffmpeg',
            '-i', video_url,
            '-c', 'copy',  # Direct copy, no re-encoding
            local_path
        ]
        subprocess.run(command, check=True, capture_output=True)
        return local_path
    except subprocess.CalledProcessError as e:
        raise Exception(f"Failed to download video: {e.stderr.decode('utf-8')}")

def download_image(image_url, draft_name, material_name):
    """
    Download image to specified directory, and convert to PNG format
    :param image_url: Image URL
    :param draft_name: Draft name
    :param material_name: Material name
    :return: Local image path
    """
    material_name = _safe_material_name(material_name)
    image_url = _validate_url(image_url)

    image_dir = f"{draft_name}/assets/image"
    os.makedirs(image_dir, exist_ok=True)
    local_path = f"{image_dir}/{material_name}"
    
    # Check if file already exists
    if os.path.exists(local_path):
        print(f"Image file already exists: {local_path}")
        return local_path
    
    try:
        # Use ffmpeg to download and convert image to PNG format
        command = [
            'ffmpeg',
            '-headers', 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36\r\nReferer: https://www.163.com/\r\n',
            '-i', image_url,
            '-vf', 'format=rgba',  # Convert to RGBA format to support transparency
            '-frames:v', '1',      # Ensure only one frame is processed
            '-y',                  # Overwrite existing files
            local_path
        ]
        subprocess.run(command, check=True, capture_output=True)
        return local_path
    except subprocess.CalledProcessError as e:
        raise Exception(f"Failed to download image: {e.stderr.decode('utf-8')}")

def download_audio(audio_url, draft_name, material_name):
    """
    Download audio and transcode to MP3 format to specified directory
    :param audio_url: Audio URL
    :param draft_name: Draft name
    :param material_name: Material name
    :return: Local audio path
    """
    material_name = _safe_material_name(material_name)
    audio_url = _validate_url(audio_url)

    audio_dir = f"{draft_name}/assets/audio"
    os.makedirs(audio_dir, exist_ok=True)
    local_path = f"{audio_dir}/{material_name}"
    
    # Check if file already exists
    if os.path.exists(local_path):
        print(f"Audio file already exists: {local_path}")
        return local_path
    
    try:
        # Use ffmpeg to download and transcode to MP3 (key modification: specify MP3 encoder)
        command = [
            'ffmpeg',
            '-i', audio_url,          # Input URL
            '-c:a', 'libmp3lame',     # Force encode audio stream to MP3
            '-q:a', '2',              # Set audio quality (0-9, 0 is best, 2 balances quality and file size)
            '-y',                     # Overwrite existing files (optional)
            local_path                # Output path
        ]
        subprocess.run(command, check=True, capture_output=True, text=True)
        return local_path
    except subprocess.CalledProcessError as e:
        raise Exception(f"Failed to download audio:\n{e.stderr}")

def download_file(url:str, local_filename, max_retries=3, timeout=180):
    # [WASHIN-SECURITY] 驗證 URL 安全
    url = _validate_url(url)

    # 检查是否是本地文件路径
    if os.path.exists(url) and os.path.isfile(url):
        # 是本地文件，直接复制
        directory = os.path.dirname(local_filename)
        
        # 创建目标目录（如果不存在）
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
            print(f"Created directory: {directory}")
        
        print(f"Copying local file: {url} to {local_filename}")
        start_time = time.time()
        
        # 复制文件
        shutil.copy2(url, local_filename)
        
        print(f"Copy completed in {time.time()-start_time:.2f} seconds")
        print(f"File saved as: {os.path.abspath(local_filename)}")
        return True
    
    # 原有的下载逻辑
    # Extract directory part
    directory = os.path.dirname(local_filename)

    retries = 0
    while retries < max_retries:
        try:
            if retries > 0:
                wait_time = 2 ** retries  # Exponential backoff strategy
                print(f"Retrying in {wait_time} seconds... (Attempt {retries+1}/{max_retries})")
                time.sleep(wait_time)
            
            print(f"Downloading file: {local_filename}")
            start_time = time.time()
            
            # Create directory (if it doesn't exist)
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
                print(f"Created directory: {directory}")

            # Add headers
            headers = {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
                'Referer': 'https://www.163.com/',  # 网易的Referer
                'Accept': 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
                'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8'
            }

            # 禁止自動 redirect（防公網 URL 302 到 localhost）
            with requests.get(url, stream=True, timeout=timeout, headers=headers,
                              allow_redirects=False) as response:
                # 如果是 redirect，驗證目標 URL 再手動跟隨
                if response.status_code in (301, 302, 303, 307, 308):
                    redirect_url = response.headers.get('Location', '')
                    _validate_url(redirect_url)  # 驗證 redirect 目標
                    return download_file(redirect_url, local_filename, max_retries - 1, timeout)
                response.raise_for_status()

                total_size = int(response.headers.get('content-length', 0))
                block_size = 65536  # 64KB chunks（原 1KB 太慢）
                
                with open(local_filename, 'wb') as file:
                    bytes_written = 0
                    for chunk in response.iter_content(block_size):
                        if chunk:
                            file.write(chunk)
                            bytes_written += len(chunk)
                            
                            if total_size > 0:
                                progress = bytes_written / total_size * 100
                                # For frequently updated progress, consider using logger.debug or more granular control to avoid large log files
                                # Or only output progress to console, not write to file
                                print(f"\r[PROGRESS] {progress:.2f}% ({bytes_written/1024:.2f}KB/{total_size/1024:.2f}KB)", end='')
                                pass # Avoid printing too much progress information in log files
                
                if total_size > 0:
                    # print() # Original newline
                    pass
                print(f"Download completed in {time.time()-start_time:.2f} seconds")
                print(f"File saved as: {os.path.abspath(local_filename)}")
                return True
                
        except Timeout:
            print(f"Download timed out after {timeout} seconds")
        except RequestException as e:
            print(f"Request failed: {e}")
        except Exception as e:
            print(f"Unexpected error during download: {e}")
        
        retries += 1
    
    print(f"Download failed after {max_retries} attempts for URL: {url}")
    return False

