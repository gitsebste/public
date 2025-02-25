import os
import json

def evaluate_results(api_call_result: str, 
                    gating_policy: dict, 
                    gating_active: bool, 
                    quiet_mode: bool,
                    use_reference_branch: bool,
                    reference_alerts: dict):
    print('\nEvaluating results for the security findings...')

    if len(api_call_result) == 0:
        print('No vulnerabilities found!')
        return

    # If no gating policy is specified, just publish vulnerabilities list with a warning
    if gating_policy is None:
        print('Gating policy is not specified, just publishing findings')
        print(f'{WARNING_PREFIX}Vulnerabilities found: {len(api_call_result)}. See details below or in "Security -> Code scanning"')
        if quiet_mode:
            print('Results are suppressed by quiet mode')
        else:
            print(json.dumps(api_call_result, sort_keys=True, indent=4))
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
            print(f'{ERROR_PREFIX}Gating policy must be specified for all severities requested for scan')
            exit(5)

        # Calculate date of grace period 
        datetime_first_seen = datetime.strptime(vulnerability['created_at'][:10], r'%Y-%m-%d')

        if use_reference_branch:
            try:
                if not quiet_mode:
                    print('Checking for vulnerability in reference branch')
                datetime_first_seen_reference = datetime.strptime(reference_alerts[vulnerability['number']][:10], r'%Y-%m-%d')
                # Only use reference branch's "firstSeenDate" if it's older then target ref's
                if datetime_first_seen_reference < datetime_first_seen:
                    datetime_first_seen = datetime_first_seen_reference
                if not quiet_mode:
                    print('Vulnerability found in reference branch')
            except KeyError:
                print('Vulnerability not found in reference branch. Proceeding evaluating grace period for given ref.')

        grace_period_end_date = (datetime_first_seen + timedelta(days=grace_period_days)).date()

        # If vulnerability is in grace period
        if date.today() <= grace_period_end_date:
            try:
                vulnerabilities_within_grace_period[severity] += 1
            except KeyError:
                vulnerabilities_within_grace_period[severity] = 1
            if not quiet_mode:
                days_left = (grace_period_end_date - date.today()).days
                print(f'{WARNING_PREFIX}Vulnerability with "{severity}" severity within grace period found!',
                        f'End date is {grace_period_end_date} ({days_left} days left).',
                        'See details below or in "Security -> Code scanning"', sep=' ')
                print(json.dumps(vulnerability, sort_keys=True, indent=4))
        # If vulnerability is out of grace period
        else:
            try:
                vulnerabilities_out_of_grace_period[severity] += 1
            except KeyError:
                vulnerabilities_out_of_grace_period[severity] = 1
            if not quiet_mode:
                print(f'{ERROR_PREFIX}Vulnerability with "{severity}" severity out of grace period found! See details below or in "Security -> Code scanning"')
                print(json.dumps(vulnerability, sort_keys=True, indent=4))

    if vulnerabilities_within_grace_period != {}:  
        print(f'{WARNING_PREFIX} vulnerabilities within grace period found: {vulnerabilities_within_grace_period}. See pipeline logs or "Security -> Code scanning" for details')

    if vulnerabilities_out_of_grace_period != {}:
        if gating_active:
            fail_pipeline = False # Flag to fail pipeline after results are published
        for severity in vulnerabilities_out_of_grace_period:
            if gating_policy[severity]['blocking'] in (True, 'True'): # Both variants for simple compatibility with json from ADO object
                print(f'{ERROR_PREFIX}Policy evaluation failed for vulnerabilities of "{severity}" severity! ',
                        f'{vulnerabilities_out_of_grace_period[severity]} {severity} vulnerabilities out of grace period found.',
                        'Go to "Security -> Code scanning" to evaluate the vulnerabilities identified', sep=' ')
                fail_pipeline = True
            else:
                print(f'{WARNING_PREFIX}{vulnerabilities_out_of_grace_period[severity]} "{severity}" vulnerabilities out of grace period found.',
                        'Go to "Security -> Code scanning" to evaluate the vulnerabilities identified', sep=' ')
        if gating_active and fail_pipeline:
            exit(2)
        else:
            print(f'{WARNING_PREFIX} vulnerabilities out of grace period found: {vulnerabilities_out_of_grace_period}. See pipeline logs or "Security -> Code scanning" for details')

def main():
    api_call_result = os.environ.get('QUERY_RESULT')
    gating_policy = json.loads(os.environ.get('GATING_POLICY'))
    gating_active = os.environ.get('GATING_ACTIVE').lower() == 'true'
    quiet_mode = os.environ.get('QUIET_MODE').lower() == 'true'
    use_reference_branch = os.environ.get('USE_REFERENCE_BRANCH').lower() == 'true'
    reference_alerts = json.loads(os.environ.get('REFERENCE_ALERTS'))

    evaluate_results(api_call_result, gating_policy, gating_active, quiet_mode, use_reference_branch, reference_alerts)

if __name__ == "__main__":
    main()
