# Amazon DynamoDB tenant isolation

## Support model

Proxima uses DynamoDB's native IAM authorization with a tenant-scoped partition key. This is an application/identity integration, not a DynamoDB wire-protocol proxy. The shared table must use the authenticated tenant ID as its partition key. Each tenant's application role receives an identity policy restricted to the exact table ARN and dynamodb:LeadingKeys equal to that tenant ID.

The trusted backend must derive tenant identity from authenticated membership and obtain credentials for the corresponding tenant role. Never trust a tenant partition key supplied only by an untrusted client.

## Rust policy generation

The module is proxima_engine::dynamodb_tenant::DynamoTenant. It validates tenant IDs and exact DynamoDB table ARNs and generates a least-privilege policy for GetItem, PutItem, UpdateItem, DeleteItem and Query. It intentionally omits Scan, PartiQL, transaction APIs, streams and table administration.

Example:

    use proxima_engine::dynamodb_tenant::DynamoTenant;
    let tenant = DynamoTenant::new(
        "tenant-a",
        "arn:aws:dynamodb:us-east-1:123456789012:table/proxima-records",
    )?;
    let policy = tenant.iam_policy();
    // Attach the identity policy to the tenant-specific IAM role.

The table partition key must actually contain the authenticated tenant ID for dynamodb:LeadingKeys to enforce the intended boundary. Do not attach a second broad role, wildcard table policy, or alternate credentials that bypass this condition. Review role trust, permissions boundaries, resource policies and organization SCPs.

## Real AWS IAM acceptance script

Run the real IAM suite in a dedicated disposable AWS account. Configure two separate AWS CLI profiles that assume tenant A and tenant B roles. Each role must have only the generated policy for its own tenant partition key and the exact table ARN. The test table must use `tenant_id` as its partition key; set `DYNAMODB_SORT_KEY` if it also has a sort key.

```bash
export AWS_REGION='us-east-1'
export AWS_PROFILE_TENANT_A='proxima-tenant-a'
export AWS_PROFILE_TENANT_B='proxima-tenant-b'
export DYNAMODB_TEST_TABLE='proxima-tenant-acceptance'
export DYNAMODB_PARTITION_KEY='tenant_id'
# Optional for a composite key:
# export DYNAMODB_SORT_KEY='record_id'
bash scripts/test-dynamodb-leading-keys-aws.sh
```

The script verifies distinct IAM principals, own-partition writes/reads, cross-tenant GetItem and Query denial, and Scan denial. It cleans up only its uniquely named canary records. Use a disposable table and dedicated test roles; never point it at production data.

## Verification boundary

Rust tests validate exact resource scoping, tenant-key binding, malformed and wildcard ARN rejection, and omission of broad actions. DynamoDB Local does not enforce AWS IAM identity policies; local CRUD is not proof of tenant isolation. Security acceptance must run in a dedicated AWS test account with two real tenant roles and verify own-partition success plus cross-tenant GetItem, Query, PutItem and Scan denial. CI must not report this AWS authorization test as passed unless it actually ran with isolated AWS credentials.

References: AWS documentation on [DynamoDB IAM condition keys](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/specifying-conditions.html) and [DynamoDB access control](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/access-control-iam.html).
