from __future__ import print_function  # Python 2/3 compatibility

import base64
import os
import logging
import argparse
import boto3
from boto3.dynamodb.conditions import Key, Attr

# boto3.setup_default_session(profile_name='my-aws')


def get_args():
    # initialize parser
    parser = argparse.ArgumentParser()
    # add arguments
    parser.add_argument(
        '-p', '--provider', help="cloud provider: aws", required=False, default='aws'
    )
    parser.add_argument(
        '-t', '--table', help="tinc dynamodb table", required=False, default='tinc-db'
    )
    parser.add_argument(
        '-r', '--table_region', help="tinc dynamodb table region", required=False, default='us-west-2'
    )
    parser.add_argument(
        '-n', '--netname', help="tinc netname", required=True
    )
    parser.add_argument(
        '-c', '--classifier', help="tinc role: hub|spoke", required=True
    )
    parser.add_argument(
        '-d', '--node_id', help="tinc node id, must be unique in netname", required=True
    )
    args = parser.parse_args()
    # Assign args to variables
    provider = args.provider
    table = args.table
    table_region = args.table_region
    netname = args.netname
    classifier = args.classifier
    node_id = args.node_id

    return provider, table, table_region, netname, classifier, node_id


def dynamo_client(table, region):
    db_client = boto3.resource('dynamodb'
                               # region_name=region,
                               # profile_name = "my-aws"
                               # aws_access_key_id="AKIAJPSLK2GP5AYDWG3Q",
                               # aws_secret_access_key="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"
                               )

    db_table = db_client.Table(table)

    return db_table


def is_active(table, node_id):
    try:
        response = table.query(KeyConditionExpression=Key('node_id').eq(node_id))
    except Exception as e:
        logging.error("e")
        raise e
    if response['Items'][0]['state'] == 'on':
        return True
    return False


def fetch_table_data(table, netname, classifier):
    """
    :param table: dynamodb table where stored tinc node configs
    :param netname: tinc netname
    :param classifier: tinc role: hub|spoke
    :return: nodes as list
    """
    # fetching tinc data based on classifier
    if classifier == 'hub':
        response = table.scan(FilterExpression=Attr("classifier").eq('spoke') & Attr("netname").eq(netname))
    elif classifier == 'spoke':
        response = table.scan(FilterExpression=Attr("classifier").eq('hub') & Attr("netname").eq(netname))
    else:
        logging.error("Wrong classifier, allowed hub|spoke")
        exit(111)

    data = response['Items']
    while 'LastEvaluatedKey' in response:
        response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
        data.extend(response['Items'])

    return data


def create_host_file(host, modified=0):
    host_file_path = '/tmp/tinc/%s/hosts/%s_%s' % (host['netname'], host['node_id'], host['classifier'])
    if os.path.exists(host_file_path):
        host_file_encoded = base64.b64encode(open(host_file_path, "r").read())
        if host_file_encoded == host['host_file']:
            logging.info("%s %s no changes, skipping" % (host['node_id'], host['classifier']))
        else:
            logging.info("Detected config change for %s %s, configuring" % (host['node_id'], host['classifier']))
            try:
                f = open(host_file_path, 'w')
                f.write(base64.b64decode(host['host_file']))
                f.close()
                logging.info("Configured %s %s" % (host['node_id'], host['classifier']))
                modified = 1
            except IOError as e:
                logging.error(e)
                raise e
    else:
        logging.info("%s %s is active, configuring" % (host['node_id'], host['classifier']))
        try:
            f = open(host_file_path, 'w')
            f.write(base64.b64decode(host['host_file']))
            f.close()
            logging.info("%s %s configured" % (host['node_id'], host['classifier']))
            modified = 1
        except IOError as e:
            logging.error(e)
            raise e

    return modified


def remove_host_file(host, modified=0):
    host_file_path = '/tmp/tinc/%s/hosts/%s_%s' % (host['netname'], host['node_id'], host['classifier'])
    try:
        os.remove(host_file_path)
        modified = 1
    except OSError as e:
        logging.info("%s %s is in inactive, skipping" % (host['node_id'], host['classifier']))

    return modified


def restart_tinc(netname):
    logging.info('Tinc restarting daemon')
    pass
    logging.info('Tinc daemon restarted successfully')


def main():

    # Get passed arguments
    provider, table, table_region, netname, classifier, cidr, node_id = get_args()
    db_table = dynamo_client(table, table_region)

    # setup logger
    log_file = 'reinit.log'
    logging.basicConfig(filename=log_file, format='%(asctime)s %(funcName)s %(levelname)s %(message)s', level=logging.INFO)

    # Fetch data from db
    data = fetch_table_data(db_table, netname, classifier)

    # static variables
    number_of_modifications = 0

    if is_active(db_table, node_id):
        for node in data:
            if node['node_id'] == node_id:
                continue
            else:
                if is_active(db_table, node['node_id']):
                    number_of_modifications = number_of_modifications + create_host_file(node)
                else:
                    number_of_modifications = number_of_modifications + remove_host_file(node)
    else:
        for node in data:
            if node['node_id'] == node_id:
                continue
            else:
                logging.info("%s %s is disabled, removing cache" % (node_id, classifier))
                number_of_modifications = number_of_modifications + remove_host_file(node)
                logging.info("%s %s cache cleared" % (node_id, classifier))

    if number_of_modifications > 0:
        restart_tinc(netname)
    else:
        logging.info('No any changes in configs, skipping Tinc restart')


if __name__ == '__main__':
    main()
