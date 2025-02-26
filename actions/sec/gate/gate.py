import os
import json
import requests
from datetime import datetime
from datetime import timedelta
from datetime import date

def str2bool(string: str):
  return str(string).lower() == 'true'

def print_if(msg: str, condition: bool):
  if condition:
    print('#'*80)
    print(msg)
    print('#'*80)

def evaluate_results(api_call_result: dict, 
                    gating_policy: dict, 
                    gating_active: bool, 
                    quiet_mode: bool,
                    use_reference_branch: bool,
                    reference_alerts: dict):
    print('\nEvaluating results for the security findings...')
    fail_pipeline = False

    if len(api_call_result) == 0:
        print('No vulnerabilities found!')
        return

    # If no gating policy is specified, just publish vulnerabilities list with a warning
    if gating_policy is None:
        print('Gating policy is not specified, just publishing findings')
        print(f'Vulnerabilities found: {len(api_call_result)}. See details below or in "Security -> Code scanning"')
        msg = 'Results are suppressed by quiet mode' if quiet_mode else json.dumps(api_call_result, sort_keys=True, indent=4)
        print(msg)
        return

    # If gating policy is specified, analyze vulnerabilities per severity taking into account grace periods
    vulnerabilities_out_of_grace_period = {}
    vulnerabilities_within_grace_period = {}

    for vulnerability in api_call_result:
        # Retrieve grace period according to the finding's severity
        severity = vulnerability['rule']['security_severity_level']
        try:
            grace_period_days = gating_policy[severity]['grace_period']
        except KeyError:
            print(f'Gating policy must be specified for all severities requested for scan')
            exit(5)

        # Calculate date of grace period 
        datetime_first_seen = datetime.strptime(vulnerability['created_at'][:10], r'%Y-%m-%d')

        if use_reference_branch:
            try:
                print_if('Checking for vulnerability in reference branch', not quiet_mode)
                datetime_first_seen_reference = datetime.strptime(reference_alerts[vulnerability['number']][:10], r'%Y-%m-%d')
                # Only use reference branch's "firstSeenDate" if it's older then target ref's
                if datetime_first_seen_reference < datetime_first_seen:
                    datetime_first_seen = datetime_first_seen_reference
                print_if('Vulnerability found in reference branch', not quiet_mode)
            except KeyError:
                print('Vulnerability not found in reference branch. Proceeding evaluating grace period for given ref.')

        grace_period_end_date = (datetime_first_seen + timedelta(days=grace_period_days)).date()

        # If vulnerability is in grace period
        if date.today() <= grace_period_end_date:
            try:
                vulnerabilities_within_grace_period[severity] += 1
            except KeyError:
                vulnerabilities_within_grace_period[severity] = 1
            print_if(' '.join([
              f'Vulnerability with "{severity}" severity within grace period found!',
              f'End date is {grace_period_end_date} ({(grace_period_end_date - date.today()).days} days left).',
              'See details below or in "Security -> Code scanning"']), not quiet_mode)
            print_if(json.dumps(vulnerability, sort_keys=True, indent=4), not quiet_mode)
        # If vulnerability is out of grace period
        else:
            try:
                vulnerabilities_out_of_grace_period[severity] += 1
            except KeyError:
                vulnerabilities_out_of_grace_period[severity] = 1
            print_if(f'Vulnerability with "{severity}" severity out of grace period found! See details below or in "Security -> Code scanning"', not quiet_mode)
            print_if(json.dumps(vulnerability, sort_keys=True, indent=4), not quiet_mode)

    if vulnerabilities_within_grace_period != {}:  
        print(f'Vulnerabilities within grace period found: {vulnerabilities_within_grace_period}. See pipeline logs or "Security -> Code scanning" for details')

    if vulnerabilities_out_of_grace_period != {}:
        for severity in vulnerabilities_out_of_grace_period:
            if str2bool(gating_policy[severity]['blocking']):
                print(f'Policy evaluation failed for vulnerabilities of "{severity}" severity! ',
                        f'{vulnerabilities_out_of_grace_period[severity]} {severity} vulnerabilities out of grace period found.',
                        'Go to "Security -> Code scanning" to evaluate the vulnerabilities identified', sep=' ')
                fail_pipeline = True
            else:
                print(f'{vulnerabilities_out_of_grace_period[severity]} "{severity}" vulnerabilities out of grace period found.',
                        'Go to "Security -> Code scanning" to evaluate the vulnerabilities identified', sep=' ')
        else:
            print(f'Vulnerabilities out of grace period found: {vulnerabilities_out_of_grace_period}. See pipeline logs or "Security -> Code scanning" for details')
    if gating_active and fail_pipeline:
      print('Policy-prohibited vulnerabilities were found')
      exit(302)

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
        print('Failed to make API call to GitHub. See response text below.')
        print(api_call_result.text)
        exit(1)
    else:
        print('Results from GitHub received successfully')

    return api_call_result.json()

def get_env_var(string: str):
  return os.environ.get(string)

def json2dict(string: str):
  return json.loads(string)

def query_main():
    github_token = get_env_var('GITHUB_TOKEN')
    owner = get_env_var('REPO_OWNER')
    repo_name = get_env_var('REPO_NAME')
    target_ref = get_env_var('TARGET_REF')
    severity_levels = get_env_var('SEVERITY_LEVELS')
    max_alerts = int(get_env_var('MAX_ALERTS'))

    query_result = query_github_code_scanning_alerts(github_token, owner, repo_name, target_ref, severity_levels, max_alerts)
    with open('query_result.json', 'w') as f:
        json.dump(query_result, f)

def evaluate_main():
    api_call_result = json2dict(get_env_var('QUERY_RESULT'))
    gating_policy = json2dict(get_env_var('GATING_POLICY'))
    gating_active = str2bool(get_env_var('GATING_ACTIVE'))
    quiet_mode = str2bool(get_env_var('QUIET_MODE'))
    use_reference_branch = str2bool(get_env_var('USE_REFERENCE_BRANCH'))
    reference_alerts = json2dict(get_env_var('REFERENCE_ALERTS')) if use_reference_branch else None

    evaluate_results(api_call_result, gating_policy, gating_active, quiet_mode, use_reference_branch, reference_alerts)

def function2name(function):
  return str(function).split()[1]

if __name__ == "__main__":
    mains = {'query': query_main, 'evaluate': evaluate_main}
    main = get_env_var('RUN')
    if main not in mains:
        print(f'{main} should be one of {",".join(mains.keys())}.')
        exit(127)
    print(f'Executing {function2name(mains[main])}')
    mains[main]()
