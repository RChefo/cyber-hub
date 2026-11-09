use serde_json::json;

use super::*;

fn rules(issues: &[Issue]) -> Vec<&str> {
    issues.iter().map(|i| i.rule.as_str()).collect()
}

#[test]
fn wildcards_match_like_iam() {
    assert!(glob("iam:*", "IAM:PassRole"));
    assert!(glob("iam:Create*", "iam:CreatePolicyVersion"));
    assert!(glob("*", "s3:GetObject"));
    assert!(glob("ec2:?unInstances", "ec2:RunInstances"));
    assert!(!glob("iam:Get*", "iam:PassRole"));
    assert!(!glob("s3:*", "s3x:GetObject"));
    assert!(glob("lambda:*Function*", "lambda:UpdateFunctionCode"));
}

#[test]
fn administrator_and_service_wide_access() {
    let admin = json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]});
    let issues = check("admin.json", &admin, None);
    assert_eq!(rules(&issues), vec!["IAM-FULL-ADMIN"], "escalation is not repeated when everything is allowed");
    assert_eq!(issues[0].severity, "critical");
    assert_eq!(issues[0].location, "admin.json › statement 1");

    let iam_all = json!({"Statement":{"Sid":"IamEverything","Effect":"Allow","Action":["iam:*","s3:GetObject"],"Resource":"*"}});
    let issues = check("ops", &iam_all, None);
    assert!(rules(&issues).contains(&"IAM-SERVICE-ADMIN"));
    let esc = issues.iter().find(|i| i.rule == "IAM-PRIVILEGE-ESCALATION").unwrap();
    assert!(esc.detail.contains("create a new version of a policy") && esc.detail.contains("attach any managed policy to a role"), "{}", esc.detail);
    assert_eq!(esc.location, "ops › statement 1 (IamEverything)");

    let scoped = json!({"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]});
    assert!(check("mfa", &scoped, None).is_empty(), "a condition narrows the grant");
}

#[test]
fn escalation_methods_need_every_action_and_respect_deny() {
    let pass_and_run = json!({"Statement":[{"Effect":"Allow","Action":["iam:PassRole","ec2:RunInstances","ec2:Describe*"],"Resource":"*"}]});
    let issues = check("ci", &pass_and_run, None);
    let esc = issues.iter().find(|i| i.rule == "IAM-PRIVILEGE-ESCALATION").unwrap();
    assert!(esc.detail.contains("start an EC2 instance with a more privileged instance profile"));
    assert!(!esc.detail.contains("Lambda"), "iam:PassRole alone is not a Lambda escalation");

    let denied = json!({"Statement":[
        {"Effect":"Allow","Action":["iam:PassRole","ec2:RunInstances"],"Resource":"*"},
        {"Effect":"Deny","Action":"ec2:Run*","Resource":"*"}]});
    assert!(!rules(&check("ci", &denied, None)).contains(&"IAM-PRIVILEGE-ESCALATION"));

    let code = json!({"Statement":[{"Effect":"Allow","Action":"lambda:UpdateFunctionCode","Resource":"*"}]});
    assert!(check("dev", &code, None)[0].detail.contains("replace the code of an existing Lambda function"));

    let read_only = json!({"Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::reports","arn:aws:s3:::reports/*"]}]});
    assert!(check("reader", &read_only, None).is_empty());

    let assume = json!({"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]});
    assert_eq!(rules(&check("hop", &assume, None)), vec!["IAM-ASSUME-ANY-ROLE"]);

    let not_action = json!({"Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]});
    let r = rules(&check("power-user", &not_action, None)).into_iter().map(String::from).collect::<Vec<_>>();
    assert!(r.contains(&"IAM-NOT-ACTION".to_string()) && r.contains(&"IAM-PRIVILEGE-ESCALATION".to_string()), "NotAction iam:* still allows lambda:UpdateFunctionCode: {r:?}");
}

#[test]
fn resource_and_trust_policies() {
    let public_bucket = json!({"Statement":[{"Sid":"PublicRead","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::site/*"}]});
    let issues = check("site bucket", &public_bucket, None);
    assert_eq!((issues[0].rule.as_str(), issues[0].severity.as_str(), issues[0].title.as_str()), ("IAM-PUBLIC", "critical", "Resource open to anyone"));

    let via_endpoint = json!({"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:*","Resource":"*","Condition":{"StringEquals":{"aws:SourceVpce":"vpce-1a2b3c"}}}]});
    assert!(check("vpc bucket", &via_endpoint, None).is_empty(), "a VPC endpoint condition limits the principal");

    let github = |sub: Option<&str>| {
        let mut st = json!({"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"}}});
        if let Some(s) = sub {
            st["Condition"]["StringLike"] = json!({"token.actions.githubusercontent.com:sub": s});
        }
        json!({"Statement":[st]})
    };
    assert_eq!(rules(&check("deploy", &github(None), None)), vec!["IAM-OIDC-ANY-SUBJECT"]);
    assert_eq!(rules(&check("deploy", &github(Some("repo:*")), None)), vec!["IAM-OIDC-ANY-SUBJECT"]);
    assert!(check("deploy", &github(Some("repo:acme/shop:ref:refs/heads/main")), None).is_empty());
    assert!(check("deploy", &github(Some("repo:acme/*")), None).is_empty(), "an organization narrows it");

    let cross = |cond: serde_json::Value| json!({"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::210987654321:root"},"Action":"sts:AssumeRole","Condition":cond}]});
    let issues = check("vendor", &cross(json!({})), None);
    assert_eq!((rules(&issues), issues[0].severity.as_str()), (vec!["IAM-CROSS-ACCOUNT-NO-EXTERNAL-ID"], "low"));
    assert!(issues[0].detail.contains("210987654321"));
    assert!(check("vendor", &cross(json!({"StringEquals":{"sts:ExternalId":"8f1c"}})), None).is_empty());
    assert!(check("vendor", &cross(json!({})), Some("210987654321")).is_empty(), "the same account is not cross-account");

    let anyone = json!({"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]});
    assert_eq!(check("open role", &anyone, None)[0].title, "Role can be assumed by anyone");
}

#[test]
fn malformed_documents_are_ignored() {
    assert!(!is_policy(&json!({"Statement":"x"})));
    assert!(check("x", &json!({"Statement":[{"Action":"*"}]}), None).is_empty(), "no Effect means no Allow");
    assert!(check("x", &json!(null), None).is_empty());
}
