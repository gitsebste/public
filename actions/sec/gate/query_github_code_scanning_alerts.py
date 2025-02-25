import os
import json

def query_github_code_scanning_alerts(
        github_token: str,
        owner: str,
        repo_name: str,
        target_ref: str,
        severity_levels: str,
        max_alerts: int):

    print(f'Evaluating vulnerabilities for branch "{target_ref}".')

    api_call_url = f'https://api.github.com/repos/{owner}/{repo_name}/code-scanning/alerts?ref={target_ref}&state=open'

    if max_alerts is not None:      
        print(f'Pulling up to {max_alerts} findings ordered by severity')
        api_call_url = api_call_url + f'&per_page={max_alerts}'

    if severity_levels is not None:
        print(f'Additional filter applied for "{severity_levels}" severities')
        api_call_url = api_call_url + f'&severity={severity_levels}'

    print(f'API call URL: {api_call_url}')
    headers = {
        'Authorization': f'token {github_token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    api_call_result = requests.get(api_call_url, headers=headers)

    if api_call_result.status_code != 200:
        print(f'{ERROR_PREFIX}Failed to make API call to GitHub. See response text below.')
        print(api_call_result.text)
        exit(1)
    else:
        print('Results from GitHub received successfully')

    return api_call_result.json()

def main():
    github_token = os.environ.get('GITHUB_TOKEN')
    owner = os.environ.get('REPO_OWNER')
    repo_name = os.environ.get('REPO_NAME')
    target_ref = os.environ.get('TARGET_REF')
    severity_levels = os.environ.get('SEVERITY_LEVELS')
    max_alerts = int(os.environ.get('MAX_ALERTS'))

    query_result = query_github_code_scanning_alerts(github_token, owner, repo_name, target_ref, severity_levels, max_alerts)
    with open('query_result.json', 'w') as f:
        json.dump(output, f)

if __name__ == "__main__":
    main()
