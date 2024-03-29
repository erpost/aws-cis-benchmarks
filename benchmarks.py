import boto3
import os
import csv


credentials = os.path.expanduser('.aws/credentials')
config = os.path.expanduser('.aws/config')


# setup local credentials file
if os.path.isfile(credentials):
    os.environ['AWS_SHARED_CREDENTIALS_FILE'] = credentials
if os.path.isfile(config):
    os.environ['AWS_CONFIG_FILE'] = config


def csv_header():
    outfile = 'CIS Benchmarks.csv'
    print('Running CIS Checks...')
    with open(outfile, 'w', newline='') as outfile:
        out_file = csv.writer(outfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
        out_file.writerow(['CIS Benchmark'] + ['Profile'] + ['Benchmark Description'] + ['Status'] + ['Resources'])


def csv_input(cis_bm, prof, bm_desc, stat, res):
    outfile = 'CIS Benchmarks.csv'
    with open(outfile, 'a', newline='') as outfile:
        out_file = csv.writer(outfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
        out_file.writerow([cis_bm] + [prof] + [bm_desc] + [stat] + [res])


def cis_1_1():
    print('CIS 1.1:  **TBD**')


def cis_1_2():
    print('CIS 1.2:  **TBD**')


def cis_1_3():
    print('CIS 1.3:  **TBD**')


def cis_1_4():
    print('CIS 1.4:  **TBD**')


def cis_1_5():
    iam = boto3.client('iam')
    account_policy = iam.get_account_password_policy()
    password_policy = account_policy['PasswordPolicy']
    upper_chars = password_policy['RequireUppercaseCharacters']

    if upper_chars is True:
        print('CIS 1.5:  Passed')
        csv_input('1.5', 'Level 1', 'IAM password policy requires at least one uppercase letter', 'Passed', 'N/A')
    else:
        print('CIS 1.5:  Failed')
        csv_input('1.5', 'Level 1', 'IAM password policy requires at least one uppercase letter', 'Failed', 'N/A')


def cis_1_6():
    iam = boto3.client('iam')
    account_policy = iam.get_account_password_policy()
    password_policy = account_policy['PasswordPolicy']
    lower_chars = password_policy['RequireLowercaseCharacters']

    if lower_chars is True:
        print('CIS 1.6:  Passed')
        csv_input('1.6', 'Level 1', 'IAM password policy requires at least one lowercase letter', 'Passed', 'N/A')
    else:
        print('CIS 1.6:  Failed')
        csv_input('1.6', 'Level 1', 'IAM password policy requires at least one lowercase letter', 'Failed', 'N/A')


def cis_1_7():
    iam = boto3.client('iam')
    account_policy = iam.get_account_password_policy()
    password_policy = account_policy['PasswordPolicy']
    req_symbol = password_policy['RequireSymbols']

    if req_symbol is True:
        print('CIS 1.7:  Passed')
        csv_input('1.7', 'Level 1', 'IAM password policy requires at least one symbol', 'Passed', 'N/A')
    else:
        print('CIS 1.7:  Failed')
        csv_input('1.7', 'Level 1', 'IAM password policy requires at least one symbol', 'Failed', 'N/A')


def cis_1_8():
    iam = boto3.client('iam')
    account_policy = iam.get_account_password_policy()
    password_policy = account_policy['PasswordPolicy']
    req_number = password_policy['RequireNumbers']

    if req_number is True:
        print('CIS 1.8:  Passed')
        csv_input('1.8', 'Level 1', 'IAM password policy requires at least one symbol', 'Passed', 'N/A')
    else:
        print('CIS 1.8:  Failed')
        csv_input('1.8', 'Level 1', 'IAM password policy requires at least one symbol', 'Failed', 'N/A')


def cis_1_9():
    iam = boto3.client('iam')
    account_policy = iam.get_account_password_policy()
    password_policy = account_policy['PasswordPolicy']
    pass_length = password_policy['MinimumPasswordLength']

    if pass_length >= 14:
        print('CIS 1.9:  Passed')
        csv_input('1.9', 'Level 1', 'IAM password policy requires minimum length of 14 or greater', 'Passed', 'N/A')
    else:
        print('CIS 1.9:  Failed')
        csv_input('1.9', 'Level 1', 'IAM password policy requires minimum length of 14 or greater', 'Failed', 'N/A')


def cis_1_10():
    iam = boto3.client('iam')
    account_policy = iam.get_account_password_policy()
    password_policy = account_policy['PasswordPolicy']
    pass_reuse = password_policy['PasswordReusePrevention']

    if pass_reuse >= 24:
        print('CIS 1.10:  Passed')
        csv_input('1.10', 'Level 1', 'IAM password policy prevents password reuse', 'Passed', 'N/A')
    else:
        print('CIS 1.10:  Failed')
        csv_input('1.10', 'Level 1', 'IAM password policy prevents password reuse', 'Failed', 'N/A')


def cis_1_11():
    iam = boto3.client('iam')
    account_policy = iam.get_account_password_policy()
    password_policy = account_policy['PasswordPolicy']
    pass_age = password_policy['MaxPasswordAge']

    if pass_age <= 90:
        print('CIS 1.11:  Passed')
        csv_input('1.11', 'Level 1', 'IAM password policy expires passwords within 90 days or less', 'Passed', 'N/A')
    else:
        print('CIS 1.11:  Failed')
        csv_input('1.11', 'Level 1', 'IAM password policy expires passwords within 90 days or less', 'Failed', 'N/A')


def cis_1_12():
    iam = boto3.client('iam')
    summary = iam.get_account_summary()
    summary_map = summary['SummaryMap']
    root_keys = summary_map['AccountAccessKeysPresent']

    if not root_keys:
        print('CIS 1.12:  Passed')
        csv_input('1.12', 'Level 1', 'No root account access key exists', 'Passed', 'N/A')
    else:
        print('CIS 1.12:  Failed')
        csv_input('1.12', 'Level 1', 'No root account access key exists', 'Failed', 'N/A')


def cis_1_13():
    iam = boto3.client('iam')
    summary = iam.get_account_summary()
    summary_map = summary['SummaryMap']
    root_mfa = summary_map['AccountMFAEnabled']

    if root_mfa:
        print('CIS 1.13:  Passed')
        csv_input('1.13', 'Level 1', 'MFA is enabled for the "root" account', 'Passed', 'N/A')
    else:
        print('CIS 1.13:  Failed')
        csv_input('1.13', 'Level 1', 'MFA is enabled for the "root" account', 'Failed', 'N/A')


def cis_1_14():
    iam = boto3.client('iam')
    list_mfa_devices = iam.list_virtual_mfa_devices()
    mfa_devices = list_mfa_devices['VirtualMFADevices']

    hardware_mfa = True

    for mfa_device in mfa_devices:
        serial_number = mfa_device['SerialNumber']
        if 'root-account-mfa-device' in serial_number:
            hardware_mfa = False

    if hardware_mfa is True:
        print('CIS 1.14:  Passed')
        csv_input('1.14', 'Level 2', 'Hardware MFA is enabled for the "root" account', 'Passed', 'N/A')
    else:
        print('CIS 1.14:  Failed')
        csv_input('1.14', 'Level 2', 'Hardware MFA is enabled for the "root" account', 'Failed', 'N/A')


def cis_1_15():
    print('CIS 1.15:  **TBD**')


if __name__ == '__main__':
    csv_header()
    cis_1_1()
    cis_1_2()
    cis_1_3()
    cis_1_4()
    cis_1_5()
    cis_1_6()
    cis_1_7()
    cis_1_8()
    cis_1_9()
    cis_1_10()
    cis_1_11()
    cis_1_12()
    cis_1_13()
    cis_1_14()
    cis_1_15()
