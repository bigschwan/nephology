#!/usr/bin/env python
import re

import boto
from boto.exception import S3ResponseError, S3CreateError
from boto.s3.lifecycle import Lifecycle

from nephoria.testcase_utils.cli_test_runner import CliTestRunner, SkipTestException
from nephoria.testcontroller import TestController
import copy
import time


class RunInstances(CliTestRunner):

    _DEFAULT_CLI_ARGS = copy.copy(CliTestRunner._DEFAULT_CLI_ARGS)

    @property
    def tc(self):
        tc = getattr(self, '__tc', None)
        if not tc:
            tc = TestController(self.args.clc,
                                password=self.args.password,
                                clouduser_name=self.args.test_user,
                                clouduser_account=self.args.test_account,
                                log_level=self.args.log_level)
            setattr(self, '__tc', tc)
        return tc

    @property
    def user(self):
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
    def bucket_prefix(self):
        bucket_prefix = getattr(self, '__bucket_prefix', None)
        if not bucket_prefix:
            bucket_prefix = "nephoria-bucket-test-suite-" + str(int(time.time()))
        return bucket_prefix

    @bucket_prefix.setter
    def bucket_prefix(self, value):
        setattr(self, '__bucket_prefix', value)

    def test_bucket_get_put_delete(self):
        test_bucket = self.bucket_prefix + "-simple-test-bucket"
        bucket = self.tc.user.s3.create_bucket(test_bucket)
        self.tc.user.s3.delete_bucket(test_bucket)

    def test_negative_basic(self):
        """
        Test Coverage:
            - create bucket with empty-string name
            - invalid bucket names
        """
        self.log.debug("Trying to create bucket with empty-string name.")
        try:
            null_bucket_name = ""
            bucket_obj = self.tc.user.s3.create_bucket(null_bucket_name)
            if bucket_obj:
                raise("Should have caught exception for creating bucket with empty-string name.")
        except S3ResponseError as e:
            assert (e.status == 405), 'Expected response status code to be 405, actual status code is ' + str(e.status)
            assert (re.search("MethodNotAllowed", e.code)),\
                "Incorrect exception returned when creating bucket with null name."

        self.log.debug("Testing an invalid bucket names, calls should fail.")

        def test_creating_bucket_invalid_names(bad_bucket):
            should_fail = False
            try:
                bucket = self.tc.user.s3.create_bucket(bad_bucket)
                should_fail = True
                try:
                    self.tc.user.s3.delete_bucket(bucket)
                except:
                    self.log.debug("Exception deleting bad bucket, shouldn't be here anyway. Test WILL fail")
            except Exception as e:
                self.log.debug("Correctly caught the exception for bucket name '" + bad_bucket + "' Reason: " + e.reason)
            if should_fail:
                raise("Should have caught exception for bad bucket name: " + bad_bucket)

        # with the EUCA-8864 fix, a new property 'objectstorage.bucket_naming_restrictions'
        # has been introduced, now 'bucket..123', 'bucket.' are actually valid bucket names
        # when using 'extended' naming convention.
        # http://docs.aws.amazon.com/AmazonS3/latest/dev/BucketRestrictions.html
        # when DNS is not being used, for now buckets can be created with bucket
        # names like '/bucket123', 'bucket123/', see EUCA-8863
        # TODO check what bucket naming convention is being used for the test
        for bad_bucket in ["bucket&123", "bucket*123"]:
            test_creating_bucket_invalid_names(self.bucket_prefix + bad_bucket)

    # def test_bucket_acl(self):
    #     '''
    #     Tests bucket ACL management and adding/removing from the ACL with both valid and invalid usernames
    #     '''
    #
    #     test_bucket = self.bucket_prefix + 'acl_bucket_test'
    #
    #     test_user_id = self.tc.user.s3.connection.get_canonical_user_id()
    #     self.log.debug('Starting ACL test with bucket name: ' + test_bucket + ' and userid ' + test_user_id)
    #
    #     try:
    #         acl_bucket = self.tc.user.s3.create_bucket(test_bucket)
    #         self.tc.user.test_user_resources['_bucket'].append(acl_bucket)
    #         self.log.debug('Created bucket: ' + test_bucket)
    #     except S3CreateError:
    #         self.log.debug("Can't create the bucket, already exists. Deleting it an trying again")
    #         try:
    #             self.tc.user.s3.delete_bucket(test_bucket)
    #             acl_bucket = self.tc.s3.create_bucket(test_bucket)
    #         except:
    #             self.log.debug("Couldn't delete and create new bucket. Failing test")
    #             raise("Couldn't make the test bucket: " + test_bucket)
    #
    #     policy = acl_bucket.get_acl()
    #
    #     if policy == None:
    #         raise('No acl returned')
    #
    #     self.log.debug(policy)
    #     # Check that the acl is correct: owner full control.
    #     if len(policy.acl.grants) > 1:
    #         self.tc.s3.delete_bucket(test_bucket)
    #         raise('Expected only 1 grant in acl. Found: ' + policy.acl.grants.grants.__len__())
    #
    #     if policy.acl.grants[0].id != test_user_id or policy.acl.grants[0].permission != 'FULL_CONTROL':
    #         self.tc.s3.delete_bucket(test_bucket)
    #         raise('Unexpected grant encountered: ' + policy.acl.grants[0].display_name + ' ' + policy.acl.grants[
    #             0].permission + ' ' + policy.acl.grants[0].id)
    #
    #     # Get the info on the owner from the ACL returned
    #     owner_display_name = policy.acl.grants[0].display_name
    #     owner_id = policy.acl.grants[0].id
    #
    #     # upload a new acl for the bucket
    #     new_acl = policy
    #     new_user_display_name = owner_display_name
    #     new_user_id = owner_id
    #     new_acl.acl.add_user_grant(permission="READ", user_id=new_user_id, display_name=new_user_display_name)
    #     try:
    #         acl_bucket.set_acl(new_acl)
    #         acl_check = acl_bucket.get_acl()
    #     except S3ResponseError:
    #         raise ("Failed to set or get new acl")
    #
    #     self.log.info("Got ACL: " + acl_check.acl.to_xml())
    #
    #     # expected_result_base='<AccessControlList>
    #     # <Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">
    #     # <ID>' + owner_id + '</ID><DisplayName>'+ owner_display_name + '</DisplayName></Grantee><Permission>FULL_CONTROL</Permission></Grant>
    #     # <Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID>EXPECTED_ID</ID><DisplayName>EXPECTED_NAME</DisplayName></Grantee><Permission>READ</Permission></Grant>
    #     # </AccessControlList>'
    #
    #     if acl_check == None and not self.tc.user.s3.check_acl_equivalence(acl1=acl_check.acl, acl2=new_acl.acl):
    #         self.tc.user.s3.delete_bucket(test_bucket)
    #         raise ("Incorrect acl length or acl not found\n. Got bucket ACL:\n" + acl_check.acl.to_xml() +
    #                "\nExpected:" + new_acl.acl.to_xml())
    #     else:
    #         self.log.info("Got expected basic ACL addition")
    #
    #     self.log.info(
    #         "Grants 0 and 1: " + acl_check.acl.grants[0].to_xml() + " -- " + acl_check.acl.grants[1].to_xml())
    #
    #     # Check each canned ACL string in boto to make sure Walrus does it right
    #     for acl in boto.s3.acl.CannedACLStrings:
    #         if acl == "authenticated-read":
    #             continue
    #         self.log.info('Testing canned acl: ' + acl)
    #         try:
    #             acl_bucket.set_acl(acl)
    #             acl_check = acl_bucket.get_acl()
    #         except Exception as e:
    #             self.tc.user.s3.delete_bucket(test_bucket)
    #             raise("Got exception trying to set acl to " + acl + ": " + str(e))
    #
    #         self.log.info("Set canned-ACL: " + acl + " -- Got ACL from service: " + acl_check.acl.to_xml())
    #         expected_acl = self.tc.user.get_canned_acl(bucket_owner_id=owner_id, canned_acl=acl,
    #                                                   bucket_owner_display_name=owner_display_name)
    #
    #         if expected_acl == None:
    #             self.tc.user.s3.delete_bucket(test_bucket)
    #             raise("Got None when trying to generate expected acl for canned acl string: " + acl)
    #
    #         if not self.tc.user.check_acl_equivalence(acl1=expected_acl, acl2=acl_check.acl):
    #             self.tc.user.s3.delete_bucket(test_bucket)
    #             raise (
    #                 "Invalid " + acl + " acl returned from Walrus:\n" + acl_check.acl.to_xml() + "\nExpected\n" + expected_acl.to_xml())
    #         else:
    #             self.log.debug("Got correct acl for: " + acl)
    #
    #     try:
    #         acl_bucket.set_acl('invalid-acl')
    #         raise ('Did not catch expected exception for invalid canned-acl')
    #     except:
    #         self.log.debug("Caught expected exception from invalid canned-acl")
    #
    #     self.tc.user.s3.delete_bucket(test_bucket)
    #     self.log.debug("Bucket ACL: PASSED")

    def test_bucket_versioning(self):
        test_bucket = self.bucket_prefix + "versioning_test_bucket"
        self.log.info('Testing bucket versioning using bucket:' + test_bucket)
        version_bucket = self.tc.user.s3.create_bucket(test_bucket)
        self.tc.user.test_user_resources['_bucket'].append(version_bucket)
        version_status = version_bucket.get_versioning_status().get("Versioning")

        # Test the default setup after bucket creation. Should be disabled.
        if version_status != None:
            version_bucket.delete()
            raise ("Expected versioning disabled (empty), found: " + str(version_status))
        elif version_status == None:
            self.log.info("Null version status returned, may be correct since it should be disabled")

        # Turn on versioning, confirm that it is 'Enabled'
        version_bucket.configure_versioning(True)
        version_status = version_bucket.get_versioning_status().get("Versioning")
        if version_status == None or version_status != "Enabled":
            version_bucket.delete()
            raise("Expected versioning enabled, found: " + str(version_status))
        elif version_status == None:
            version_bucket.delete()
            raise("Null version status returned")
        self.log.info("Versioning of bucket is set to: " + version_status)

        # Turn off/suspend versioning, confirm.
        version_bucket.configure_versioning(False)
        version_status = version_bucket.get_versioning_status().get("Versioning")
        if version_status == None or version_status != "Suspended":
            version_bucket.delete()
            raise("Expected versioning suspended, found: " + str(version_status))
        elif version_status == None:
            version_bucket.delete()
            raise("Null version status returned")

        self.log.info("Versioning of bucket is set to: " + version_status)

        version_bucket.configure_versioning(True)
        version_status = version_bucket.get_versioning_status().get("Versioning")
        if version_status == None or version_status != "Enabled":
            version_bucket.delete()
            raise("Expected versioning enabled, found: " + str(version_status))
        elif version_status == None:
            version_bucket.delete()
            raise("Null version status returned")

        self.log.info("Versioning of bucket is set to: " + version_status)

        # version_bucket.delete()
        # self.buckets_used.remove(test_bucket)
        self.log.info("Bucket Versioning: PASSED")

    def clean_method(self):
        for bkt in self.tc.user.test_user_resources['_bucket']:
            self.user.s3.delete_bucket(bkt)


if __name__ == "__main__":
    test = RunInstances()
    result = test.run()
    exit(result)

