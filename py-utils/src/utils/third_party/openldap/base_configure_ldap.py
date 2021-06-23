#!/usr/bin/env python3
#
# Copyright (c) 2021 Seagate Technology LLC and/or its Affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# For any questions about this software or licensing,
# please email opensource@seagate.com or cortx-questions@seagate.com.
#
import os
import ldap
import glob
from shutil import copyfile
from cortx.utils.log import Log

class BaseConfig:

    def cleanup(forceclean):
	    # Removing schemas
        user_schema_file = '/etc/openldap/slapd.d/cn=config/cn=schema/cn={1}s3user.ldif'
        try:
            os.remove(user_schema_file)
        except:
            Log.debug('Error while deleting '+ user_schema_file)
            raise Exception("Error while deleting"+user_schema_file)

        filelist = glob.glob('/etc/openldap/slapd.d/cn=config/cn=schema/*ppolicy.ldif')
        for policyfile in filelist:
            try:
                os.remove(policyfile)
            except:
                Log.debug('Error while deleting '+ policyfile)
                raise Exception("Error while deleting"+policyfile)

        module_files = ["cn=module{0}.ldif","cn=module{1}.ldif","cn=module{2}.ldif"]
        for module_file in enumerate(module_files):
            module_file = '/etc/openldap/slapd.d/cn=config/'+module_file
            try:
                os.remove(module_file)
            except:
               Log.debug('Error while deleting '+ module_file)
               raise Exception('Error while deleting ' + module_file)


        mdb_directory = '/etc/openldap/slapd.d/cn=config/olcDatabase={2}mdb'
        try:
            files = glob.glob('/etc/openldap/slapd.d/cn=config/olcDatabase={2}mdb/*')
            for f in files:
                try:
                    os.remove(f)
                except:
                    Log.debug('Error while deleting '+ f)
                    raise Exception('Error while deleting '+ f)
        except:
            Log.debug('Error while deleting '+ mdb_directory)
        mdbfile = '/etc/openldap/slapd.d/cn=config/olcDatabase={2}mdb.ldif'
        try:
            os.remove(mdbfile)
        except:
            Log.debug('Error while deleting '+mdbfile)
            raise Exception('Error while deleting '+mdbfile)
        #Data Cleanup
        if forceclean == 'True' :
            files = glob.glob('/var/lib/ldap/*')
            for f in files:
                try:
                    os.remove(f)
                except:
                    Log.debug('Error while deleting '+ f)
                    raise Exception('Error while deleting '+ f)

    def performBaseConfig(rootpassword,defaultpassword,forcecleanup):
        defaultpasswd=False
        forceclean=False
        ROOTDNPASSWORD=None

        ROOTDNPASSWORD = rootpassword
        if defaultpassword != None :
            defaultpasswd = defaultpassword
        if forcecleanup != None :
            forceclean = forcecleanup

        INSTALLDIR="/opt/seagate/cortx/s3/install/ldap"
        cleanup(forceclean)

        copyfile(INSTALLDIR+'/olcDatabase={2}mdb.ldif' ,\
        '/etc/openldap/slapd.d/cn=config/olcDatabase={2}mdb.ldif')

        os.system('chgrp ldap /etc/openldap/certs/password')

        if ROOTDNPASSWORD == None :
            if defaultpasswd == 'True' :
                ROOTDNPASSWORD = 'seagate'
            else :
                ROOTDNPASSWORD = input("Enter password for LDAP RootDN ")
        cmd = 'slappasswd -s ' + ROOTDNPASSWORD
        pwd = os.popen(cmd).read()
        pwd.replace('/','\/')
        #restart slapd post cleanup
        os.system('systemctl restart slapd')
        # Open a connection
        ldap_conn = ldap.initialize("ldapi:///")

        # Bind/authenticate with a user with apropriate rights to add objects
        ldap_conn.simple_bind_s("cn=admin,dc=seagate,dc=com",ROOTDNPASSWORD)


        ldap_conn.sasl_non_interactive_bind_s('EXTERNAL')
        dn="olcDatabase={0}config,cn=config"
        mod_attrs = [( ldap.MOD_REPLACE, 'olcRootDN', [b'cn=admin,cn=config'] )]
        try:
            ldap_conn.modify_s(dn,mod_attrs)
        except:
            Log.debug('Error while modifying olcRootDN attribute for olcDatabase={0}config')
            raise Exception('Error while modifying olcRootDN attribute for olcDatabase={0}config')

        mod_attrs = [( ldap.MOD_REPLACE, 'olcRootPW', pwd.encode("utf-8") )]
        try:
            ldap_conn.modify_s(dn,mod_attrs)
        except:
            Log.debug('Error while modifying olcRootPW attribute for olcDatabase={0}config')
            raise Exception('Error while modifying olcRootPW attribute for olcDatabase={0}config')
        mod_attrs = [( ldap.MOD_REPLACE, 'olcAccess', [b'{0}to * by dn.base="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth" write by self write by * read'] )]
        try:
            ldap_conn.modify_s(dn,mod_attrs)
        except:
            Log.debug('Error while modifying olcAccess attribute for olcDatabase={0}config')
            raise Exception('Error while modifying olcAccess attribute for olcDatabase={0}config')

        dn="olcDatabase={2}mdb,cn=config"
        mod_attrs = [( ldap.MOD_REPLACE, 'olcSuffix', [b'dc=seagate,dc=com'] )]
        try:
            ldap_conn.modify_s(dn,mod_attrs)
        except:
            Log.debug('Error while modifying olcSuffix attribute for olcDatabase={2}mdb')
            raise Exception('Error while modifying olcSuffix attribute for olcDatabase={2}mdb')

        mod_attrs = [( ldap.MOD_REPLACE, 'olcRootDN', [b'cn=admin,dc=seagate,dc=com'] )]
        try:
            ldap_conn.modify_s(dn,mod_attrs)
        except:
            Log.debug('Error while modifying olcRootDN attribute for olcDatabase={2}mdb')
            raise Exception('Error while modifying olcRootDN attribute for olcDatabase={2}mdb')

        mod_attrs = [( ldap.MOD_ADD, 'olcDbMaxSize', [b'10737418240'] )]
        try:
            ldap_conn.modify_s(dn,mod_attrs)
        except:
            Log.debug('Error while modifying olcDbMaxSize attribute for olcDatabase={2}mdb')
            raise Exception('Error while modifying olcDbMaxSize attribute for olcDatabase={2}mdb')

        mod_attrs = [( ldap.MOD_REPLACE, 'olcRootPW', pwd.encode("utf-8") )]
        try:
            ldap_conn.modify_s(dn,mod_attrs)
        except:
            Log.debug('Error while modifying olcRootPW attribute for olcDatabase={2}mdb')
            raise Exception('Error while modifying olcRootPW attribute for olcDatabase={2}mdb')

        mod_attrs = [( ldap.MOD_REPLACE, 'olcAccess', [b'{0}to attrs=userPassword by self write by dn.base="cn=admin,dc=seagate,dc=com" write by anonymous auth by * none'] )]
        try:
            ldap_conn.modify_s(dn,mod_attrs)
        except:
            Log.debug('Error while modifying olcAccess attribute for attrs=userPassword and dn.base=cn=admin,dc=seagate,dc=com in olcDatabase={2}mdb')
            raise Exception('Error while modifying olcAccess attribute for attrs=userPassword and dn.base=cn=admin,dc=seagate,dc=com in olcDatabase={2}mdb')

        mod_attrs = [( ldap.MOD_ADD, 'olcAccess', [b'{1}to * by dn.base="cn=admin,dc=seagate,dc=com" write by self write by * none'] )]
        try:
            ldap_conn.modify_s(dn,mod_attrs)
        except:
            Log.debug('Error while modifying olcAccess attribute for * and dn.base=cn=admin,dc=seagate,dc=com in olcDatabase={2}mdb')
            raise Exception('Error while modifying olcAccess attribute for * and dn.base=cn=admin,dc=seagate,dc=com in olcDatabase={2}mdb')

        mod_attrs = [( ldap.MOD_REPLACE, 'olcAccess', [b'{0}to attrs=userPassword by self write by dn.base="cn=sgiamadmin,dc=seagate,dc=com" write by anonymous auth by * none'] )]
        try:
            ldap_conn.modify_s(dn,mod_attrs)
        except:
            Log.debug('Error while modifying olcAccess attribute for attrs=userPassword and dn.base=cn=sgiamadmin,dc=seagate,dc=com in olcDatabase={2}mdb')
            raise Exception('Error while modifying olcAccess attribute for attrs=userPassword and dn.base=cn=sgiamadmin,dc=seagate,dc=com in olcDatabase={2}mdb')

        mod_attrs = [( ldap.MOD_ADD, 'olcAccess', [b'{1}to * by dn.base="cn=sgiamadmin,dc=seagate,dc=com" write by self write by * none'] )]
        try:
            ldap_conn.modify_s(dn,mod_attrs)
        except:
            Log.debug('Error while modifying olcAccess attribute for * and dn.base=cn=sgiamadmin,dc=seagate,dc=com in olcDatabase={2}mdb')
            raise Exception('Error while modifying olcAccess attribute for * and dn.base=cn=sgiamadmin,dc=seagate,dc=com in olcDatabase={2}mdb')

        ldap_conn.unbind_s()


        #add_s - init.ldif
        # Open a connection
        ldap_conn = ldap.initialize("ldapi:///")

        # Bind/authenticate with a user with apropriate rights to add objects
        ldap_conn.simple_bind_s("cn=admin,dc=seagate,dc=com",ROOTDNPASSWORD)

        dn="dc=seagate,dc=com"
        add_record = [
         ('dc', [b'seagate'] ),
         ('o', [b'seagate'] ),
         ('description', [b'Root entry for seagate.com.']),
         ('objectClass', [b'top',b'dcObject',b'organization'])
        ]
        try:
            ldap_conn.add_s(dn, add_record)
        except:
            Log.debug('Error while adding dc=seagate,dc=com')
            raise Exception('Error while adding dc=seagate,dc=com')

        ldap_conn.unbind_s()

        #add iam constraint
        ldap_conn = ldap.initialize("ldapi:///")
        ldap_conn.simple_bind_s("cn=admin,cn=config",ROOTDNPASSWORD)
        dn="cn=module{0},cn=config"
        add_record = [
         ('cn', [b'module{0}'] ),
         ('olcModulePath', [b'/usr/lib64/openldap/'] ),
         ('olcModuleLoad', [b'unique.la'] ),
         ('objectClass', [b'olcModuleList'])
        ]
        try:
            ldap_conn.add_s(dn, add_record)
        except:
            Log.debug('Error while adding IAM constraint cn=module{0},cn=config')
            raise Exception('Error while adding IAM constraint cn=module{0},cn=config')

        dn="olcOverlay=unique,olcDatabase={2}mdb,cn=config"
        add_record = [
         ('olcUniqueUri', [b'ldap:///?mail?sub?'] ),
         ('olcOverlay', [b'unique'] ),
         ('objectClass', [b'olcOverlayConfig',b'olcUniqueConfig'])
        ]
        try:
            ldap_conn.add_s(dn, add_record)
        except:
            Log.debug('Error while adding IAM constraint olcOverlay=unique')
            raise Exception('Error while adding IAM constraint olcOverlay=unique')

        #add ppolicyModule
        dn="cn=module{1},cn=config"
        add_record = [
         ('cn', [b'module{1}'] ),
         ('olcModulePath', [b'/usr/lib64/openldap/'] ),
         ('olcModuleLoad', [b'ppolicy.la'] ),
         ('objectClass', [b'olcModuleList'])
        ]
        try:
            ldap_conn.add_s(dn, add_record)
        except:
            Log.debug('Error while adding IAM constraint cn=module{1},cn=config')
            raise Exception('Error while adding IAM constraint cn=module{1},cn=config')

        ldap_conn.unbind_s()
