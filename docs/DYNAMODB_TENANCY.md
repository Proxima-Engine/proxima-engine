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

## Verification boundary

Rust tests validate exact resource scoping, tenant-key binding, malformed and wildcard ARN rejection, and omission of broad actions. DynamoDB Local does not enforce AWS IAM identity policies; local CRUD is not proof of tenant isolation. Security acceptance must run in a dedicated AWS test account with two real tenant roles and verify own-partition success plus cross-tenant GetItem, Query, PutItem and Scan denial. CI must not report this AWS authorization test as passed unless it actually ran with isolated AWS credentials.

References: AWS documentation on [DynamoDB IAM condition keys](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/specifying-conditions.html) and [DynamoDB access control](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/access-control-iam.html).
