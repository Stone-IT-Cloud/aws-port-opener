"""
This module contains the Lambda function to update the security group rules for SSH access.
"""

import json
import pprint

import ipaddr
from boto3 import Session


def compare_rule(rule, from_port, to_port, proto, description):
    """
    Compare the given rule with the provided parameters.

    Args:
        rule (dict): The rule to compare.
        from_port (int): The expected from port.
        to_port (int): The expected to port.
        proto (str): The expected protocol.
        description (str): The expected description.

    Returns:
        bool: True if the rule matches the provided parameters, False otherwise.
    """
    if rule["FromPort"] != from_port:
        return None
    if rule["ToPort"] != to_port:
        return None
    if rule["IpProtocol"] != proto:
        return None

    for ipv4_rule in rule["IpRanges"]:
        if description in ipv4_rule["Description"]:
            return {"IpRanges": ipv4_rule, "Ipv6Ranges": None}
    for ipv6_rule in rule["Ipv6Ranges"]:
        if description in ipv6_rule["Description"]:
            return {"IpRanges": None, "Ipv6Ranges": ipv6_rule}

    return None


def get_ip_version(ip):
    """
    Returns the IP version (IPv4 or IPv6) of the given IP address.

    Args:
        ip (str): The IP address.

    Returns:
        int: The IP version (4 for IPv4, 6 for IPv6).
    """
    result = ipaddr.IPAddress(ip)
    return result.version


def lambda_handler(event, context):
    """
    Lambda function to update the security group rules for SSH access.

    Args:
        event (dict): The event data passed to the Lambda function.
        context (object): The runtime information of the Lambda function.

    Returns:
        dict: The response containing the status code and body message.
    """
    # Retrieve the caller's IP address from the event
    caller_ip = event["requestContext"]["identity"]["sourceIp"]

    # Retrieve the username of the IAM role or user invoking the function
    caller_username = event["requestContext"]["identity"]["userArn"].split("/")[-1]
    print(f"Caller IP address: {caller_ip}")
    print(f"Caller username: {caller_username}")
    # Initialize AWS clients
    boto_sess = Session()
    ec2 = boto_sess.client("ec2")

    # Define security group parameters
    security_group_id = "sg-039172ef467bb6bdf"
    port = 22
    ip_protocol = "tcp"

    # Describe existing security group rules
    response = ec2.describe_security_groups(GroupIds=[security_group_id])
    existing_rules = response["SecurityGroups"][0]["IpPermissions"]

    # Check if there's an existing rule for the user
    user_rule = None
    for rule in existing_rules:
        print("*** Evaluationg rule: ")
        data = json.loads(json.dumps(rule))
        pprint.pprint(data, compact=True)
        # if "Description" in rule and caller_username in rule["Description"]:
        if r := compare_rule(rule, port, port, ip_protocol, caller_username):
            user_rule = rule
            user_rule["IpRanges"] = r["IpRanges"] is not None and [r["IpRanges"]] or []
            user_rule["Ipv6Ranges"] = (
                r["Ipv6Ranges"] is not None and [r["Ipv6Ranges"]] or []
            )
            break

    # If there's an existing rule, check if the IP address needs to be updated
    version = get_ip_version(caller_ip)
    rule = {}
    if version == 4:
        rule = {
            "IpProtocol": ip_protocol,
            "FromPort": port,
            "ToPort": port,
            "IpRanges": [
                {
                    "CidrIp": f"{caller_ip}/32",
                    "Description": f"{caller_username} SSH access",
                }
            ],
        }
    else:
        rule = {
            "IpProtocol": ip_protocol,
            "FromPort": port,
            "ToPort": port,
            "Ipv6Ranges": [
                {
                    "CidrIpv6": f"{caller_ip}/128",
                    "Description": f"{caller_username} SSH access",
                }
            ],
        }

    if user_rule:
        print(f"User rule: {user_rule}")
        existing_ip = (
            len(user_rule["IpRanges"]) > 0
            and user_rule["IpRanges"][0]["CidrIp"]
            or user_rule["Ipv6Ranges"][0]["CidrIpv6"]
        )
        if existing_ip != f"{caller_ip}/32":
            # Update existing rule with new IP address
            print(f"Updating rule: {user_rule} to {rule}")

            ec2.revoke_security_group_ingress(
                GroupId=security_group_id, IpPermissions=[user_rule]
            )

            ec2.authorize_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=[rule],
            )
    else:
        # Create a new rule for the caller's IP address
        print(f"Creating new rule: {rule}")
        ec2.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=[rule],
        )

    return {"statusCode": 200, "body": "Security group updated successfully."}
