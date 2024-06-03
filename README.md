# aws-port-opener - AWS Lambda Function to Update SSH Security Group Rules

This AWS Lambda function dynamically updates an EC2 security group to allow SSH access from the IP address of the caller. It ensures that the security group rules are always up-to-date with the current IP addresses of authorized users.

## Prerequisites

Before deploying this Lambda function, ensure you have the following:

- An AWS account with necessary permissions to manage security groups and Lambda functions.
- AWS CLI configured with appropriate IAM permissions.

## Deployment

1. **Install Required Libraries**

   Ensure you have `boto3` and `ipaddr` libraries installed. If you're using a deployment package, include these dependencies.

   ```bash
   pip install boto3 ipaddr -t .
   ```

2. **Create the Lambda Function**

   Zip your Lambda function code along with the dependencies:

   ```bash
   zip -r lambda_function.zip .
   ```

   Create the Lambda function using the AWS CLI:

   ```bash
   aws lambda create-function \
       --function-name UpdateSshSecurityGroup \
       --zip-file fileb://lambda_function.zip \
       --handler lambda_function.lambda_handler \
       --runtime python3.8 \
       --role arn:aws:iam::<your-account-id>:role/<your-lambda-execution-role>
   ```

3. **Set Up API Gateway**

   To trigger the Lambda function via HTTP requests, set up an API Gateway:

   - Create a new API.
   - Create a resource and method (e.g., POST) and integrate it with your Lambda function.
   - Deploy the API and note the endpoint URL.

## Usage

When the Lambda function is triggered, it performs the following steps:

1. Retrieves the caller's IP address and IAM username from the API Gateway event.
2. Describes the current security group rules.
3. Checks if a rule already exists for the caller's username.
4. Updates the rule if the IP address has changed, or creates a new rule if none exists.
5. Returns a response indicating the success of the operation.

## Function Logic

### compare_rule

Compares a given security group rule with specified parameters. Returns the matching rule's details if found.

### get_ip_version

Determines whether a given IP address is IPv4 or IPv6.

### lambda_handler

The main function that gets invoked when the Lambda function is triggered. It handles retrieving caller information, initializing AWS clients, describing existing rules, checking for existing rules, and updating or creating rules.

## Example Event

The Lambda function expects an event from API Gateway with the following structure:

```json
{
    "requestContext": {
        "identity": {
            "sourceIp": "203.0.113.0",
            "userArn": "arn:aws:iam::123456789012:user/username"
        }
    }
}
```

## Return Value

The function returns a JSON object indicating the status of the update:

```json
{
    "statusCode": 200,
    "body": "Security group updated successfully."
}
```

## Notes

- Ensure the security group ID is correctly specified in the script.
- The function assumes that the security group rules include descriptions containing the caller's username.
- Proper IAM roles and permissions are required for the Lambda function to modify security group rules.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
```

Feel free to customize this `README.md` file further based on your specific requirements or deployment process.