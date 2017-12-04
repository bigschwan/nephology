#!/usr/bin/env python
from nephoria.testcase_utils.aws_cli_test_runner import AWSCliTestRunner, SkipTestException
from nephoria.testcontroller import TestController
from nephoria.usercontext import UserContext
from boto.cloudformation.stack import Stack
from boto.ec2.group import Group
import boto3
import copy
import re
import time


"""
This is intended to demonstrate some ways to write a basic test suite.

To run this test from the command line:

## First see what CLI args are provided. Note the --sample-arg added in the test vs the default
## arguments provided by the AWSCliTestRunner Class
prompt# python verify_instance_health_stack.py -h

## Run the tests
prompt# python verify_instance_health_stack.py --clc a.b.c.d --password mypass

## Run a subset of the tests
prompt# python verify_instance_health_stack.py --clc a.b.c.d --test-list 'test1, test12_skip_me'


To run this test from a python shell:
prompt# ipython
In [1]: from nephoria.cloudtests.instances.run_instances import RunInstances
In [2]: test = RunInstances(clc='a.b.c.d', password='mypass')
In [3]: test.run()

# Or call the method directly...
In [4]: test.test1()
"""


class VerifyInstanceHealthStack(AWSCliTestRunner):

    #####################################################################################
    # Example of how to edit, add, remove the pre-baked cli arguments provided in the base
    # AWSCliTestRunner class...
    #####################################################################################

    _DEFAULT_CLI_ARGS = copy.copy(AWSCliTestRunner._DEFAULT_CLI_ARGS)

    _DEFAULT_CLI_ARGS['vm_count'] = {'args': ['--vm-count'],
                                     'kwargs': {'help': 'Number of VMs to run',
                                                'default': 1,
                                                'type': int}}
    _DEFAULT_CLI_ARGS['instance_timeout'] = {
        'args': ['--instance-timeout'],
        'kwargs': {'help': 'Time to wait for an instance to run',
                   'default': 300,
                   'type': int}}

    _DEFAULT_CLI_ARGS['subnet_id'] = {
        'args': ['--subnet_id'],
        'kwargs': {'help': 'Subnet ID for use in test',
                   'default': None}}

    _DEFAULT_CLI_ARGS['group'] = {
        'args': ['--group'],
        'kwargs': {'help': 'Security Group for use in test',
                   'default': 'default'}}

    _DEFAULT_CLI_ARGS['keypair'] = {
        'args': ['--keypair'],
        'kwargs': {'help': 'Keypair for use in test',
                   'default': None}}

    _DEFAULT_CLI_ARGS['domain'] = {
        'args': ['--domain'],
        'kwargs': {'help': 'domain for use in test',
                   'default': 'amazonaws.com'}}

    _DEFAULT_CLI_ARGS['access_key'] = {
        'args': ['--access-key'],
        'kwargs': {'help': 'Access key to use during test',
                   'default': None}}

    _DEFAULT_CLI_ARGS['secret_key'] = {
        'args': ['--secret-key'],
        'kwargs': {'help': 'Secret key to use during test',
                    'default': None}}

    #####################################################################################
    # Populate the most commonly needed test artifacts by using dynamic properties, rather
    # than in self.__init__()...
    #####################################################################################

    @property
    def tc(self):
        tc = getattr(self, '__tc', None)
        if not tc:
            tc = TestController(self.args.clc,
                                cloudadmin_accesskey=self.access_key,
                                cloudadmin_secretkey=self.secret_key,
                                password=self.args.password,
                                clouduser_name=self.args.test_user,
                                clouduser_account=self.args.test_account,
                                log_level=self.args.log_level,
                                domain="amazonaws.com")
            setattr(self, '__tc', tc)
        return tc

    @property
    def user(self):
        if self.args.access_key and self.args.secret_key \
                and self.args.domain == "amazonaws.com":
                user = UserContext(aws_access_key=self.args.access_key,
                                   aws_secret_key=self.args.secret_key,
                                   domain=self.args.domain,
                                   region=self.args.region,
                                   )
        else:
            user = getattr(self, '__user', None)
            if not user:
                try:
                    user = self.tc.get_user_by_name(aws_account_name=self.args.test_account,
                                                    aws_user_name=self.args.test_user)
                except:
                    user = self.tc.create_user_using_cloudadmin(aws_account_name=self.args.test_account,
                                                                aws_user_name=self.args.test_user)
                setattr(self, '__user', user)
        return user

    @property
    def emi(self):
        emi = getattr(self, '__emi', None)
        if not emi:
            if self.args.emi:
                emi = self.user.ec2.get_emi(emi=self.args.emi)
            else:
                try:
                    emi = self.user.ec2.get_emi(location='cirros')
                except:
                    pass
                if not emi:
                    emi = self.user.ec2.get_emi()
            setattr(self, '__emi', emi)
        return emi

    @emi.setter
    def emi(self, value):
        setattr(self, '__emi', value)

    @property
    def keypair_name(self):
        keyname = getattr(self, '__keypairname', None)
        if not keyname:
            keyname = "{0}_{1}".format(self.__class__.__name__, int(time.time()))
        return keyname

    @property
    def keypair(self):
        key = getattr(self, '__keypair', None)
        return key

    @property
    def group(self):
        group = getattr(self, '__group', None)
        return group

    @group.setter
    def group(self, value):
        if value is None or isinstance(value, Group):
            setattr(self, '__group', value)
        else:
            raise ValueError('Can not set security group to type:"{0/{1}"'
                             .format(value, type(value)))

    @property
    def subnet_id(self):
        subnet_id = getattr(self, '__subnet_id', None)
        return subnet_id

    @subnet_id.setter
    def subnet_id(self, value):
        setattr(self, '__subnet_id', value)

    #####################################################################################
    # Create the test methods...
    #####################################################################################

    def test1_run_instances(self):
        """
        Attempts to run the number of instances provided by the vm_count param
        """
        ins = self.user.ec2.run_image(image=self.emi, keypair=self.keypair,
                                      min=self.args.vm_count, max=self.args.vm_count,
                                      zone=self.args.zone, vmtype=self.args.vmtype,
                                      group=self.group,
                                      timeout=self.args.instance_timeout,
                                      subnet_id=self.subnet_id
                                      )
        setattr(self, 'instances', ins)

    def test3_practitest_8577_verify_instance_health_template_stack(self):
        # get all stacks
        all_stacks = [s.stack_name for s in self.user.cloudformation.connection.describe_stacks()]
        for item in all_stacks:
            match = re.search("Master-InstanceHealthTemplate", item)
            if match:
                print("Found instance health stack: {}".format(item))

    def test4_practitest_8577_verify_instance_health_log_group(self):
        client = boto3.client('logs', region_name='us-east-1',
                              aws_access_key_id=self.user.access_key,
                              aws_secret_access_key=self.user.secret_key)
        response = client.describe_log_groups(
            logGroupNamePrefix='InstanceHealth')
        if len(response['logGroups']) == 1:
            print(response["logGroups"][0]["logGroupName"])

    def test5_practitest_8577_verify_instance_health_messages_log_group(self):
        client = boto3.client('logs', region_name='us-east-1',
                              aws_access_key_id=self.user.access_key,
                              aws_secret_access_key=self.user.secret_key)
        response = client.describe_log_streams(logGroupName='InstanceHealth')
        if len(response['logStreams']) == 1:
            print(response['logStreams'][0]['logStreamName'])

    def test6_practitest_8577_verify_instance_health_message_topic_sns(self):
        client = boto3.client('sns', region_name='us-east-1',
                              aws_access_key_id=self.user.access_key,
                              aws_secret_access_key=self.user.secret_key)
        for i in client.list_topics()['Topics']:
            match = re.search("InstanceHealthMessage", i['TopicArn'])
            if match:
                print("found {}".format(match.group()))

    def test7_practitest_8577_verify_rLambdaRoleHealthHandler_role(self):
        client = boto3.client('iam', region_name='us-east-1',
                              aws_access_key_id=self.user.access_key,
                              aws_secret_access_key=self.user.secret_key)
        roles = client.list_roles()
        for item in roles['Roles']:
            match = re.search("rLambdaRoleHealthHandler", item['RoleName'])
            if match:
                print("FOUND: {}".format(item['RoleName']))

    def clean_method(self):
        instances = getattr(self, 'instances', [])
        keypair = getattr(self, '__keypair', None)
        self.user.ec2.terminate_instances(instances)
        if keypair:
            self.user.ec2.delete_keypair(self.keypair)



if __name__ == "__main__":

    test = VerifyInstanceHealthStack()
    result = test.run()
    exit(result)

