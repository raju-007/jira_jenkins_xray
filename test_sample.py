import requests
import logging
import datetime
import json
import sys, os
import pytest
import pytest_xray
from collections import OrderedDict
myPath = os.path.dirname(os.path.abspath(__file__))

URL = "https://auth.test.caspar.ai/"
ACL_URL = "https://acl.test.caspar.ai/"
validate_api_dict = {}
HEADERS = {
    'Content-Type': "application/json",
    'cache-control': "no-cache",
					}
# set up logger
logger = logging.getLogger(__name__)
logger.info('=*=*=*=*= Starting new execution to run '
            'api tests for Authorization {} =*=*=*=*='
            .format(datetime.datetime.now()))

users_login_password_dict = dict(
                lab_property_manager_dict=dict(
                  email = 'kamal+lab_property_manager@caspar.ai',
                  password = 'iBrjW{Nu+2GcQ3tpyHrQ',
                ),
                lab_property_staff_dict=dict(
                  email = 'kamal+lab_property_staff@caspar.ai',
                  password = '8ejA[JCTY*RKdPvr9jhv',
                ),
                lab_sales_engineer_dict=dict(
                  email = 'kamal+lab_sales_engineer@caspar.ai',
                  password = '*vy9DXVpfXdQyegL2J{D',
                ),
                lab_super_admin_dict=dict(
                  email = 'kamal+lab_super_admin@caspar.ai',
                  password = 'KNTBv^NNY6U6v.asEUTB',
                ),
                lab_t2_internal_support_dict=dict(
                  email = 'kamal+lab_t2_internal_support@caspar.ai',
                  password = 'srWTmn4B*{huCmimn2cw',
                ),
                lab_dict=dict(
                  email = 'kamal+lab@caspar.ai',
                  password = 'bUaRfyPD8UMQRG6',
                ),
)

user_signup_data = dict(
                email='mohmad.edris_terralogic_lab89@terralogic.com',
                password='Testing1234',
                confirmPassword='Testing1234',
                cellphone='9663599533'
)
def log_test_class(name, doc_str, type):
    """
    Generate log for test class execution
    :param name: Class name
    :param doc_str: Class doc string
    :param type: <bool> begin/end <-> True/False
    """
    if type:  # Represents beginning of test class execution
        log_text = '***| Executing Test Class :' \
                   ' {} |*** ***| {} |***'.format(name, doc_str)
    else:  # Represents ending of test class execution
        log_text = '*.*.* Finished Test Class : {} *.*.*'.format(name)
    logger.info(log_text)


def log_test_method(name, doc_str, type):
    """
    Generate log for test method execution
    :param name: Method(TestCase) name
    :param doc_str: Method doc string
    :param type: <bool> begin/end <-> True/False
    """
    if type:  # Represents beginning of test class execution
        log_text = '==| Executing Test Case : {} |== ==| {} |=='\
            .format(name, doc_str)
    else:
        log_text = '*=* Finished Test Case : {} *=*'.format(name)
    logger.info(log_text)


def _login_user(email, password):
    """Make a request and return the response"""
    url = URL + "login"
    payload = {'email': email, 'password': password}
    response = requests.request("POST", url,
                                data=json.dumps(payload), headers=HEADERS)
    return response

def _logout_user(token):
    """Make a request and return the response"""
    url = URL + "logout"
    HEADER = {'Authorization': token}
    response = requests.request("POST", url, headers=HEADER)
    return response

def _getuseracl(token):
    """Make a request and return the response"""
    url = ACL_URL + "acl"
    HEADER = {'Authorization': token}
    response = requests.request("GET", url, headers=HEADER)
    return response

def _validate_user_acl(validation_api_dict, token):
    """Make a request and return the response"""
    url = ACL_URL + "Validation"
    payload = validation_api_dict
    validation_headers = HEADERS
    validation_headers.update(Authorization = token)
    response = requests.request("POST", url,
                                data=json.dumps(payload), headers=validation_headers)
    return response

def _signup_user(token, email, passwd, cpasswd, cellphone):
    """
    Make a request and return the response
    :param token: Admin Token
    :param email: User email to signup
    :param passwd: password for the user
    :param cpasswd: Confirm Password for the user
    :param cellphone: cellphone no of user
    """
    url = URL + "signup"
    validation_headers = HEADERS
    validation_headers.update(Authorization=token)
    
    user_data = OrderedDict()
    user_data['email'] = email
    user_data['password'] = passwd
    user_data['confirmPassword'] = cpasswd
    user_data['cellphone'] = cellphone
    response = requests.request("POST", url,
                                data=json.dumps(user_data), headers=validation_headers)
    return response

def _forgot_password(email):
    """Make a request and return the response
    :param email: User email """
    url = URL + "forgot"
    payload = {'email': email}
    response = requests.request("POST", url,
                                data=json.dumps(payload), headers=HEADERS)
    return response

def _reset_password(token,password,confirmPassword):
    """
        Make a request and return the response
        :param token: User Token
        :param password: password for the user
        :param confirmPassword: Confirm Password for the user
        """
    url = URL + "reset"
    payload = {'token': token, 'password': password, 'confirmPassword': confirmPassword}
    response = requests.request("POST", url,
                                data=json.dumps(payload), headers=HEADERS)
    return response

def _change_password(token,currentpassword,password,confirmPassword):
    """
        Make a request and return the response
        :param token: User Token
        :param currentpassword: User Current Password
        :param password: New password of the user
        :param confirmPassword: Confirm New Password of the user
        """
    url = URL + "changepwd"
    payload = {'currentPassword': currentpassword,'password': password, 'confirmPassword': confirmPassword}
    validation_headers = HEADERS
    validation_headers.update(Authorization=token)
    response = requests.request("POST", url,
                                data=json.dumps(payload), headers=validation_headers)
    return response

class TestAuthorization:
    """Verify the authorization for ACL service"""
    @classmethod
    def setup_class(cls):
        log_test_class(cls.__name__.strip(), cls.__doc__.strip(), True)

    @classmethod
    def teardown_class(cls):
        log_test_class(cls.__name__.strip(), cls.__doc__.strip(), False)
    def setup_method(self, method):
        log_test_method(method.__name__.strip(), method.__doc__.strip(), True)

    def teardown_method(self, method):
        log_test_method(method.__name__.strip(), method.__doc__.strip(), False)

    @pytest.fixture()
    def setUp(self):
        """Setup def for Verify the user is able to login using correct credentials
        and receives a JWT token"""
        logger.info('running test setUp for login at: {}'
                        .format(type(datetime.datetime.now())))
        num_diff_role_user = len(users_login_password_dict)
        for i in range(num_diff_role_user):
            user_role = list(users_login_password_dict.keys())[i]
            response = _login_user(users_login_password_dict[user_role]['email'],
                                   users_login_password_dict[user_role]['password'])
            resp_in_json = response.json()
            if response.status_code == 200 and 'token' in resp_in_json:
                users_login_password_dict[user_role].update(token=resp_in_json['token'])
            assert response.status_code == 200 and 'token' in resp_in_json

    @pytest.mark.xray(test_key="T3-1", test_exec_key="T3-1")
    def test_api_TR_1_0_1(self):
        """Verify the user is able to login using correct password and correct email"""
        logger.info('running test test_api_TR_1_0_1 at: {}'
                        .format(type(datetime.datetime.now())))
        num_diff_role_user = len(users_login_password_dict)
        for i in range(num_diff_role_user):
            user_role = list(users_login_password_dict.keys())[i]
            #login with valid user email and valid password
            response = _login_user(users_login_password_dict[user_role]['email'],
                                   users_login_password_dict[user_role]['password'])
            resp_in_json = response.json()
            if response.status_code == 200 and 'token' in resp_in_json:
                users_login_password_dict[user_role].update(token=resp_in_json['token'])
            assert response.status_code == 200 and 'token' in resp_in_json

    @pytest.mark.xray(test_key="T3-2", test_exec_key="T3-2")
    def test_api_TR_1_0_2(self):
        """Verify the user is not able to login using incorrect password and correct email"""
        logger.info('running test test_api_TR_1_0_2 at: {}'
                        .format(type(datetime.datetime.now())))
        num_diff_role_user = len(users_login_password_dict)
        for i in range(num_diff_role_user):
            #login with valid user email id and invalid password
            user_role = list(users_login_password_dict.keys())[i]
            response = _login_user(users_login_password_dict[user_role]['email'],
                                   "abcbUaRfyPD8UMQ")
            resp_in_json = response.json()
            assert response.status_code == 400

    @pytest.mark.xray(test_key="T3-3", test_exec_key="T3-3")
    def test_api_TR_1_0_3(self):
        """Verify the user is not able to login using correct password and incorrect email"""
        logger.info('running test test_api_TR_1_0_3 at: {}'
                    .format(type(datetime.datetime.now())))
        #login with correct password and incorrect email
        response = _login_user("kamal+prof@caspar.ai", "bUaRfyPD8UMQRG6")
        resp_in_json = response.json()
        assert response.status_code == 400

