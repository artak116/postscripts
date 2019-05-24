#!/usr/bin/python
# TODO: Add tagging support

DOCUMENTATION = '''
---
module: dynamodb_item
short_description: put an item into a DynamoDB table
description:
  - Put an item into a DynamoDB table
requirements: [ json, botocore, boto3 ]
options:
    state:
        description:
          - The desiredtem into the DynamoDB table
        required: false
        default: present
        choices: ["present", "absent"]
    table:
        description:
          - The name of the DynamoDB table
        required: true
    item:
        description:
          - The item to put
        required: false
    key:
        description:
          - The key to delete
        required: false
extends_documentation_fragment:
    - aws
    - ec2
'''

EXAMPLES = '''
# Note: These examples do not set authentication details, see the AWS Guide for details.
- dynamodb_item:
    state: "present"
    table: "test-table"
    item: "{\"key\": {\"S\": \"aaaaa\"}, \"value\": {\"S\": \"bbbb\"}}"
'''

RETURN = '''
changes:
    description: Details of created, modified or deleted item.
    returned: when creating, deleting or modifying an DynamoDB item
    type: complex
    contains:
        old_item:
            description:
              - The old item
        new_item:
            description:
              - The new item
'''
try:
    import boto3
    import botocore
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ec2 import boto3_conn, ec2_argument_spec, get_aws_connection_info, AnsibleAWSError


def get_dynamodb_table_key(conn, table):
    key_schema = conn.describe_table(TableName=table)['Table']['KeySchema']

    return [key['AttributeName'] for key in key_schema
            if key['KeyType'] == 'HASH'][0]


def get_dynamodb_item(conn, table, key):
    return conn.get_item(TableName=table, Key=key)


def put_dynamodb_item(conn, table, item):
    return conn.put_item(TableName=table, Item=item, ReturnValues='ALL_OLD')


def delete_dynamodb_item(conn, table, key):
    return conn.delete_item(TableName=table, Key=key, ReturnValues='ALL_OLD')


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
        state=dict(required=False, choices=['present', 'absent'], default='present'),
        table=dict(required=True, type='str'),
        item=dict(required=False, type='str'),
        key=dict(required=False, type='str')
    ))

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    if not HAS_BOTO3:
        module.fail_json(msg='boto3 is required.')

    # Check parameters
    if module.params['state'] == 'present':
        if 'item' not in module.params or module.params['item'] is None:
            module.fail_json(msg="To put an item, it must be specified")
    elif module.params['state'] == 'absent':
        if 'key' not in module.params or module.params['key'] is None:
            module.fail_json(msg="To delete an item, its key must be specified")

    # Apply module
    try:
        region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
        if not region:
            module.fail_json(msg="Region must be specified as a parameter, in EC2_REGION or AWS_REGION environment variables or in boto configuration file")
        conn = boto3_conn(module, conn_type='client', resource='dynamodb',
                          region=region, endpoint=ec2_url, **aws_connect_kwargs)
    except boto.exception.NoAuthHandlerFound as e:
        self.module.fail_json(msg="Can't authorize connection - %s" % str(e))

    results = dict(changed=False)
    if module.check_mode:
        if module.params['state'] == 'present':
            item_dict = json.loads(module.params['item'])
            key_name = get_dynamodb_table_key(conn, module.params['table'])
            key = {key_name: item_dict[key_name]}
            item = get_dynamodb_item(conn, module.params['table'], key)['Item']
            results['new_item'] = item_dict
            results['old_item'] = item
            results['changed'] = item_dict != item
        elif module.params['state'] == 'absent':
            response = get_dynamodb_item(conn, module.params['table'],
                                         json.loads(module.params['key']))
            results['old_item'] = response.get('Item', {})
            results['changed'] = 'Item' in response
    else:
        if module.params['state'] == 'present':
            item_dict = json.loads(module.params['item'])
            response = put_dynamodb_item(conn, module.params['table'], item_dict)
            results['new_item'] = item_dict
            results['old_item'] = response.get('Attributes', {})
            results['changed'] = (results['new_item'] != results['old_item'])
        elif module.params['state'] == 'absent':
            response = delete_dynamodb_item(conn, module.params['table'],
                                            json.loads(module.params['key']))
            results['old_item'] = response.get('Attributes', {})
            results['changed'] = (results['old_item'] != {})

    module.exit_json(**results)


if __name__ == '__main__':
    main()