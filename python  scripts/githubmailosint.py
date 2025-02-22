#!/usr/bin/env python3
import re
import sys
import json
import argparse
import threading
from requests import get
from requests.auth import HTTPBasicAuth

# -------------------------------
# ARGUMENT PARSING
# -------------------------------
parser = argparse.ArgumentParser(description="GitHub Info & Email Extractor")
parser.add_argument('target', help='GitHub target (user, org or repo URL)')
parser.add_argument('-o', help='Output file for JSON', dest='output')
parser.add_argument('-u', help='Your GitHub username (for auth)', dest='uname')
parser.add_argument('-t', help='Number of threads', dest='threads', type=int, default=2)
parser.add_argument('--org', help='Indicates target is an organization', dest='org', action='store_true')
parser.add_argument('--breach', help='Check emails for breaches via HaveIBeenPwned', dest='breach', action='store_true')
args = parser.parse_args()

target_input = args.target.strip().rstrip('/')
uname = args.uname or ''
thread_count = args.threads
check_breach = args.breach
output_file = args.output
isOrganization = args.org

# -------------------------------
# TERMINAL COLORS SETUP
# -------------------------------
# For simplicity, we use colors unless on certain platforms.
machine = sys.platform.lower()
if machine.startswith(('win', 'darwin', 'ios')):
    colors = False
else:
    colors = True

if colors:
    END = '\033[1;m'
    GREEN = '\033[1;32m'
    RED = '\033[1;31m'
    YELLOW = '\033[1;33m'
    INFO_BRACKETS = f" \033[1;31m[\033[0m"
    END_BRACKETS = f"\033[1;31m]\033[0m"
else:
    END = GREEN = RED = YELLOW = INFO_BRACKETS = END_BRACKETS = ''

print(f"{GREEN}\n\t Developed by: github.com/zebbern\n{END}")

# -------------------------------
# GLOBAL STORAGE
# -------------------------------
jsonOutput = {}

# -------------------------------
# HELPER FUNCTIONS
# -------------------------------
def extract_emails(text):
    """
    Extract emails using two methods:
      1. Emails within angle brackets (e.g. <user@example.com>).
      2. The provided mailto regex.
    Returns a unique list of emails.
    """
    emails = set()
    # Method 1: Find emails inside angle brackets.
    for email in re.findall(r'<([^>\s]+@[^>\s]+)>', text):
        emails.add(email)
    # Method 2: Provided regex for mailto:
    for email in re.findall(r'(?<=mailto:)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+', text):
        emails.add(email)
    return list(emails)

def get_user_profile(username):
    """
    Retrieves additional GitHub profile info:
      - Name, Bio, Avatar URL.
    """
    url = f'https://api.github.com/users/{username}'
    response = get(url, auth=HTTPBasicAuth(uname, ''))
    if response.status_code == 200:
        data = response.json()
        return {
            'name': data.get('name') or username,
            'bio': data.get('bio') or "No bio available.",
            'avatar_url': data.get('avatar_url') or "No avatar available."
        }
    return {'name': username, 'bio': '', 'avatar_url': ''}

def find_contributors_from_repo(username, repo):
    """
    Uses GitHub API to fetch contributors for a repository.
    """
    url = f'https://api.github.com/repos/{username}/{repo}/contributors?per_page=100'
    response = get(url, auth=HTTPBasicAuth(uname, ''))
    contributors = []
    try:
        contributors = [contrib['login'] for contrib in response.json()]
    except Exception:
        pass
    return contributors

def find_repos_from_username(username):
    """
    Retrieves non-forked repos for a given username.
    """
    url = f'https://api.github.com/users/{username}/repos?per_page=100&sort=pushed'
    response = get(url, auth=HTTPBasicAuth(uname, ''))
    repos = []
    try:
        for repo in response.json():
            if not repo.get('fork', True):
                repos.append(repo.get('name'))
    except Exception:
        pass
    return repos

def find_email_from_contributor(owner, repo, contributor):
    """
    Uses the GitHub commits API to get the latest commit by the contributor,
    extracts the commit author's email from the JSON response and then fetches
    the commit patch for additional emails using regex.
    """
    commits_url = f'https://api.github.com/repos/{owner}/{repo}/commits?author={contributor}&per_page=1'
    response = get(commits_url, auth=HTTPBasicAuth(uname, ''))
    commits = response.json()
    if not commits:
        print(f"{RED}[-]{END} No commits found for contributor {contributor} in repo {repo}")
        return None

    commit_data = commits[0]
    primary_email = commit_data.get('commit', {}).get('author', {}).get('email', None)
    commit_hash = commit_data.get('sha', None)
    if not primary_email or not commit_hash:
        print(f"{RED}[-]{END} Unable to extract email or commit hash for {contributor}")
        return None

    # Fetch the patch for extra email extraction.
    patch_url = f'https://github.com/{owner}/{repo}/commit/{commit_hash}.patch'
    patch_response = get(patch_url, auth=HTTPBasicAuth(uname, ''))
    patch_text = patch_response.text
    extra_emails = extract_emails(patch_text)
    # Ensure primary email is included.
    if primary_email not in extra_emails:
        extra_emails.insert(0, primary_email)

    # Optionally, check breach status.
    if check_breach:
        jsonOutput.setdefault(contributor, {})['email'] = primary_email
        hibp_url = f'https://haveibeenpwned.com/api/v2/breachedaccount/{primary_email}'
        if get(hibp_url).status_code == 200:
            primary_email += f"{INFO_BRACKETS}pwned{END_BRACKETS}"
            jsonOutput[contributor]['pwned'] = True
        else:
            jsonOutput[contributor]['pwned'] = False
    else:
        jsonOutput[contributor] = primary_email

    return primary_email, extra_emails

def find_email_from_username(username):
    """
    For a given username, iterate through their repos and try to get a valid email.
    """
    repos = find_repos_from_username(username)
    for repo in repos:
        result = find_email_from_contributor(username, repo, username)
        if result:
            email, extra_emails = result
            profile = get_user_profile(username)
            print_profile(username, profile, email, extra_emails)
            break
    else:
        print(f"{RED}[-]{END} No email found for user {username}")

def find_emails_from_repo(owner, repo):
    """
    For a repository, iterate through contributors to extract emails.
    """
    contributors = find_contributors_from_repo(owner, repo)
    print(f"{YELLOW}[!]{END} Total contributors: {GREEN}{len(contributors)}{END}")
    for contributor in contributors:
        result = find_email_from_contributor(owner, repo, contributor)
        if result:
            email, extra_emails = result
            profile = get_user_profile(contributor)
            print_profile(contributor, profile, email, extra_emails)
        else:
            print(f"{RED}[-]{END} No email found for contributor {contributor}")

def find_users_from_organization(org_name):
    """
    Uses the GitHub API to retrieve organization members.
    """
    url = f'https://api.github.com/orgs/{org_name}/members?per_page=100'
    response = get(url, auth=HTTPBasicAuth(uname, ''))
    members = []
    try:
        members = [member['login'] for member in response.json()]
    except Exception:
        pass
    return members

def print_profile(username, profile, email, extra_emails):
    """
    Prints the user’s details in a clean, colorful format.
    """
    print(f"\n{GREEN}User: {username}{END}")
    print(f"  Name       : {profile.get('name')}")
    print(f"  Bio        : {profile.get('bio')}")
    print(f"  Avatar URL : {profile.get('avatar_url')}")
    print(f"  Email      : {email}")
    if len(extra_emails) > 1:
        extras = ', '.join([e for e in extra_emails if e != email])
        print(f"  Extra Mails: {extras}")

def threader(function, arg_list):
    threads = []
    for arg in arg_list:
        task = threading.Thread(target=function, args=(arg,))
        threads.append(task)
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

def flash(function, arg_list):
    for i in range(0, len(arg_list), thread_count):
        chunk = arg_list[i:i+thread_count]
        threader(function, chunk)

# -------------------------------
# MAIN LOGIC
# -------------------------------
targetOrganization = targetRepo = targetUser = False
# Determine target type by counting slashes.
if target_input.count('/') < 4:
    if '/' in target_input:
        username = target_input.split('/')[-1]
    else:
        username = target_input
    if isOrganization:
        targetOrganization = True
    else:
        targetUser = True
elif target_input.count('/') == 4:
    parts = target_input.split('/')
    username = parts[-2]
    repo = parts[-1]
    targetRepo = True
else:
    print(f"{RED}[-]{END} Invalid input format")
    sys.exit(1)

if targetOrganization:
    members = find_users_from_organization(username)
    if members:
        flash(find_email_from_username, members)
    else:
        print(f"{RED}[-]{END} No members found for organization {username}")
elif targetUser:
    find_email_from_username(username)
elif targetRepo:
    find_emails_from_repo(username, repo)

# Write JSON output if specified.
if output_file:
    with open(output_file, 'w+') as f:
        json.dump(jsonOutput, f, indent=4)
