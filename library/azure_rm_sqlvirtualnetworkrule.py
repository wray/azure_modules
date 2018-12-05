#!/usr/bin/python
#
# Copyright (c) 2018, Wray Mills
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: azure_rm_sqlvirtualnetworkrule
version_added: "2.7"
short_description: Manage SQL Virtual Network Rules
description:
    - Add/Delete Virtual network Rule.

options:
    resource_group:
        description:
            - The name of the resource group that contains the resource. You can obtain this value from the Azure Resource Manager API or the portal.
        required: True
    server_name:
        description:
            - The name of the sql server.
        required: True
    name:
        description:
            - The name of the firewall rule.
        required: True
    subnet_name:
        description:
            - The name of the subnet
        required: True
    state:
      description:
        - Assert the state of the VNet rule. Use 'present' to add a rule and 'absent' to delete it.
      default: present
      choices:
        - absent
        - present

extends_documentation_fragment:
    - azure

author:
    - "Wray Mills (@wray)"

'''

EXAMPLES = '''
  - name: Create (or update) Virutal Network Rule
    azure_rm_sqlvirtualnetworkrule:
      resource_group: vnrulecrudtest-17
      server_name: vnrulecrudtest-6234
      name: vnrulecrudtest-5332
      subnet_name: vnrulecrudtest-333
'''

RETURN = '''
id:
    description:
        - Resource ID.
    returned: always
    type: str
    sample: "/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/vnrulecrudtest-17/providers/Microsoft.Sql/servers/firewallrulecrudtest-6234
             5/firewallRules/firewallrulecrudtest-5332"
'''

import time
from ansible.module_utils.azure_rm_common import AzureRMModuleBase

try:
    from msrestazure.azure_exceptions import CloudError
    from msrestazure.azure_operation import AzureOperationPoller
    from msrest.polling import LROPoller
    from azure.mgmt.sql import SqlManagementClient
    from msrest.serialization import Model
except ImportError:
    # This is handled in azure_rm_common
    pass


class Actions:
    NoAction, Create, Delete = range(3)


class AzureRMVirtualNetworkRules(AzureRMModuleBase):
    """Configuration class for an Azure RM Firewall Rule resource"""

    def __init__(self):
        self.module_arg_spec = dict(
            resource_group=dict(
                type='str',
                required=True
            ),
            server_name=dict(
                type='str',
                required=True
            ),
            name=dict(
                type='str',
                required=True
            ),
            subnet_name=dict(
                type='str',
                required=True
            ),
            state=dict(
                type='str',
                default='present',
                choices=['present', 'absent']
            )
        )

        self.resource_group = None
        self.server_name = None
        self.name = None
        self.virtual_network = None
        self.subnet_name = None

        self.results = dict(changed=False)
        self.state = None
        self.to_do = Actions.NoAction

        super(AzureRMVirtualNetworkRules, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                   supports_check_mode=True,
                                                   supports_tags=False)

    def exec_module(self, **kwargs):
        """Main module execution method"""

        for key in list(self.module_arg_spec.keys()):
            if hasattr(self, key):
                setattr(self, key, kwargs[key])

        old_response = self.get_virtualnetworkrule()
        response = None

        if not old_response:
            self.log("Virtual Network Rule instance doesn't exist")
            if self.state == 'absent':
                self.log("Old Rule didn't exist")
            else:
                self.to_do = Actions.Create
        else:
            self.log("Virtual Network Rule instance already exists")
            if self.state == 'absent':
                self.to_do = Actions.Delete
            elif self.state == 'present':
                self.log("Virtual Network Rule will remain")

        if self.to_do == Actions.Create:
            self.log("Need to Create the Virtual Network Rule instance")

            if self.check_mode:
                self.results['changed'] = True
                return self.results

            response = self.create_virtualnetworkrule()

            if not old_response:
                self.results['changed'] = True
            else:
                self.results['changed'] = old_response.__ne__(response)
            self.log("Creation done")
        elif self.to_do == Actions.Delete:
            self.log("Virtual Network Rule instance to be deleted")
            self.results['changed'] = True

            if self.check_mode:
                return self.results

            self.delete_virtualnetworkrule()
            # make sure instance is actually deleted, for some Azure resources, instance is hanging around
            # for some time after deletion -- this should be really fixed in Azure
            while self.get_virtualnetworkrule():
                time.sleep(20)
        else:
            self.log("Virtual Network Rule instance unchanged")
            self.results['changed'] = False
            response = old_response

        if response:
            self.results["id"] = response["id"]

        return self.results

    def create_virtualnetworkrule(self):
        '''
        Creates or updates Virtual Network Rule with the specified configuration.

        :return: deserialized Network Rule instance state dictionary
        '''
        self.log("Creating the Virtual Network Rule instance {0}".format(self.name))

        try:
            response = self.sql_client.virtual_network_rules.create_or_update(resource_group_name=self.resource_group,
                                                                              server_name=self.server_name,
                                                                              virtual_network_rule_name=self.name,
                                                                              virtual_network_subnet_id=self.subnet_name)

            if isinstance(response, AzureOperationPoller):
                response = self.get_poller_result(response)

        except CloudError as exc:
            self.log('Error attempting to create the Firewall Rule instance.')
            self.fail("Error creating the Firewall Rule instance: {0}".format(str(exc)))
        return response.as_dict()

    def delete_virtualnetworkrule(self):
        '''
        Deletes specified Firewall Rule instance in the specified subscription and resource group.

        :return: True
        '''
        self.log("Deleting the Firewall Rule instance {0}".format(self.name))
        try:
            response = self.sql_client.virtual_network_rules.delete(resource_group_name=self.resource_group,
                                                             server_name=self.server_name,
                                                             virtual_network_rule_name=self.name)
        except CloudError as e:
            self.log('Error attempting to delete the Firewall Rule instance.')
            self.fail("Error deleting the Firewall Rule instance: {0}".format(str(e)))

        return True

    def get_virtualnetworkrule(self):
        '''
        Gets the properties of the specified Virtual Network Rule.

        :return: deserialized Virtual Network Rule instance state dictionary
        '''
        self.log("Checking if the Virtual network Rule instance {0} is present".format(self.name))
        found = False
        try:
            response = self.sql_client.virtual_network_rules.get(resource_group_name=self.resource_group,
                                                                 server_name=self.server_name,
                                                                 virtual_network_rule_name=self.name)
            found = True
            self.log("Response : {0}".format(response))
            self.log("Virtual Network Rule instance : {0} found".format(response.name))
        except CloudError as e:
            self.log('Did not find the Virtual Network Rule instance.')
        if found is True:
            return response.as_dict()

        return False


def main():
    """Main execution"""
    AzureRMVirtualNetworkRules()


if __name__ == '__main__':
    main()

