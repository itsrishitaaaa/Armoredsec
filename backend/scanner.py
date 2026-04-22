import boto3
import json


def scan_cloud_config():

    alerts = []

    # load AWS credentials
    with open("config.json") as f:
        config = json.load(f)

    access_key = config["aws_access_key"]
    secret_key = config["aws_secret_key"]
    region = config["region"]

    # AWS clients
    s3 = boto3.client(
        "s3",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region
    )

    ec2 = boto3.client(
        "ec2",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region
    )

    iam = boto3.client(
        "iam",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key
    )

    # ---------------- S3 BUCKET CHECKS ----------------

    try:

        buckets = s3.list_buckets()["Buckets"]

        for bucket in buckets:

            name = bucket["Name"]

            # -------- PUBLIC BUCKET CHECK --------

            try:

                status = s3.get_bucket_policy_status(Bucket=name)

                if status["PolicyStatus"]["IsPublic"]:

                    alerts.append((
                        f"Public S3 Bucket: {name}",
                        "High",
                        "Disable public bucket access"
                    ))

            except:
                pass

            # -------- ENCRYPTION CHECK --------

            try:

                s3.get_bucket_encryption(Bucket=name)

            except s3.exceptions.ClientError as e:

                error_code = e.response["Error"]["Code"]

                if error_code == "ServerSideEncryptionConfigurationNotFoundError":

                    alerts.append((
                        f"S3 Bucket Not Encrypted: {name}",
                        "Medium",
                        "Enable default encryption on the bucket"
                    ))

    except Exception as e:
        print("S3 scan error:", e)

    # ---------------- EC2 SECURITY GROUP CHECK ----------------

    try:

        groups = ec2.describe_security_groups()["SecurityGroups"]

        for group in groups:

            group_name = group["GroupName"]

            for perm in group["IpPermissions"]:

                if "IpRanges" in perm:

                    for ip in perm["IpRanges"]:

                        if ip.get("CidrIp") == "0.0.0.0/0":

                            port = perm.get("FromPort", "All")

                            alerts.append((
                                f"Open EC2 Port {port} in Security Group: {group_name}",
                                "High",
                                "Restrict public inbound traffic"
                            ))

    except Exception as e:
        print("EC2 scan error:", e)

    # ---------------- IAM USER CHECK ----------------

    try:

        users = iam.list_users()["Users"]

        if len(users) > 5:

            alerts.append((
                "Too Many IAM Users",
                "Low",
                "Review unused IAM users"
            ))

    except Exception as e:
        print("IAM scan error:", e)

    return alerts