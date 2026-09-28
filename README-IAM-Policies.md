# INC-41556 IAM Policy Files

These files are identity-based policies for IAM users or roles.

- INC41556-KMSInventoryReader-ACCOUNT_ID_TEMPLATE.json: use the same read-only policy in every account assigned aws-kms-inventory-reader. The policy does not contain an account-specific ARN, so no account ID replacement is required.
- INC41556-S3CentralBucketPolicyOperator.json: Log Archive bucket-policy/configuration operator.
- INC41556-S3KMSMonitoringDataReader.json: read-only access to AWSLogs, current, history and athena-results prefixes.
- INC41556-KMSCollectorOperator.json: Shared Account Lambda/EventBridge/collector-role operator.
- INC41556-KMSAthenaGlueOperator.json: Shared Account Athena/Glue operator.
- INC41556-KMSGrafanaQueryOperator.json: Shared Account Grafana query identity/operator.

Important: cross-account access to the Log Archive bucket also requires the S3 bucket policy to allow the relevant principal. An explicit Deny from an SCP, permission boundary, identity policy or session policy overrides these Allow statements.
