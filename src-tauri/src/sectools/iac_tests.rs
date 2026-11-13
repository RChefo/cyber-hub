// SPDX-License-Identifier: Apache-2.0
use super::*;

fn rules(r: &FileReport) -> Vec<&str> {
    r.issues.iter().map(|i| i.rule.as_str()).collect()
}

fn at<'a>(r: &'a FileReport, location: &str) -> Vec<&'a str> {
    r.issues.iter().filter(|i| i.location.starts_with(location)).map(|i| i.rule.as_str()).collect()
}

const MAIN_TF: &str = r#"
variable "public" { default = false }

resource "aws_s3_bucket" "site" {
  bucket = "acme-site"
}

resource "aws_s3_bucket_acl" "site" {
  bucket = aws_s3_bucket.site.id
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "site" {
  bucket                  = aws_s3_bucket.site.id
  block_public_acls       = false
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = var.public
}

resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_db_instance" "main" {
  engine              = "postgres"
  publicly_accessible = true
}

resource "aws_db_instance" "replica" {
  publicly_accessible = var.public
  storage_encrypted   = var.encrypted
}

resource "aws_instance" "app" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"
}

resource "aws_instance" "hardened" {
  ami = "ami-0123456789abcdef0"
  metadata_options {
    http_tokens = "required"
  }
}

resource "aws_iam_role" "deploy" {
  name = "github-deploy"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" } }
    }]
  })
}

resource "aws_iam_policy" "builder" {
  name   = "builder"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Action": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], "Resource": "*"}]
}
EOF
}

resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.deploy.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

data "aws_iam_policy_document" "public_read" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::acme-site/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

resource "aws_lambda_function_url" "hook" {
  function_name      = "hook"
  authorization_type = "NONE"
}

resource "aws_cloudtrail" "main" {
  name           = "main"
  enable_logging = false
}

resource "aws_kms_key" "data" {
  description = "data"
}
"#;

#[test]
fn terraform_configuration() {
    let r = analyze("infra/main.tf", MAIN_TF, "auto").unwrap();
    assert_eq!((r.kind.as_str(), r.error.as_str()), ("terraform", ""));
    assert_eq!(at(&r, "aws_s3_bucket_acl.site"), vec!["AWS-S3-PUBLIC-ACL"]);
    let pab = r.issues.iter().find(|i| i.rule == "AWS-S3-PUBLIC-ACCESS-BLOCK").unwrap();
    assert!(pab.detail.starts_with("block_public_acls is not set"), "a reference (var.public) is not reported: {}", pab.detail);
    assert_eq!(at(&r, "aws_security_group.web"), vec!["AWS-SG-ADMIN-OPEN"], "443 to everyone and 5432 to 10/8 are fine");
    let mut db = at(&r, "aws_db_instance.main");
    db.sort_unstable();
    assert_eq!(db, vec!["AWS-DB-PUBLIC", "AWS-DB-UNENCRYPTED"]);
    assert!(at(&r, "aws_db_instance.replica").is_empty(), "variables are not resolved, so not reported");
    assert_eq!(at(&r, "aws_instance.app"), vec!["AWS-IMDSV1"]);
    assert!(at(&r, "aws_instance.hardened").is_empty());
    assert_eq!(at(&r, "aws_iam_role.deploy trust policy"), vec!["IAM-OIDC-ANY-SUBJECT"], "jsonencode of a literal object is read");
    assert_eq!(at(&r, "aws_iam_policy.builder"), vec!["IAM-PRIVILEGE-ESCALATION"], "a heredoc policy is read");
    assert_eq!(at(&r, "aws_iam_role_policy_attachment.admin"), vec!["AWS-IAM-ADMIN-ATTACHED"]);
    assert_eq!(at(&r, "data.aws_iam_policy_document.public_read"), vec!["IAM-PUBLIC"]);
    assert_eq!(at(&r, "aws_lambda_function_url.hook"), vec!["AWS-LAMBDA-PUBLIC-URL"]);
    let mut trail = at(&r, "aws_cloudtrail.main");
    trail.sort_unstable();
    assert_eq!(trail, vec!["AWS-CLOUDTRAIL-NO-VALIDATION", "AWS-CLOUDTRAIL-OFF", "AWS-CLOUDTRAIL-ONE-REGION"]);
    assert_eq!(at(&r, "aws_kms_key.data"), vec!["AWS-KMS-NO-ROTATION"]);
    assert_eq!(r.issues[0].severity, "critical", "sorted by severity: {:?}", rules(&r));

    let broken = analyze("bad.tf", "resource \"aws_s3_bucket\" {", "auto").unwrap();
    assert!(broken.error.starts_with("not valid HCL"), "{}", broken.error);
}

#[test]
fn terraform_plans_and_json_configuration() {
    let plan = serde_json::json!({
        "format_version": "1.2",
        "planned_values": { "root_module": {
            "resources": [{ "address": "aws_security_group.all", "mode": "managed", "type": "aws_security_group", "name": "all",
                "values": { "ingress": [{ "from_port": 0, "to_port": 0, "protocol": "-1", "cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": [] }] } }],
            "child_modules": [{ "resources": [{ "address": "module.db.aws_db_instance.this", "mode": "managed", "type": "aws_db_instance", "name": "this",
                "values": { "publicly_accessible": false, "storage_encrypted": true } }] }]
        } },
        "prior_state": { "values": { "root_module": { "resources": [{ "address": "data.aws_iam_policy_document.p", "mode": "data", "type": "aws_iam_policy_document", "name": "p",
            "values": { "json": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}" } }] } } }
    });
    let r = analyze("plan.json", &plan.to_string(), "auto").unwrap();
    assert_eq!(r.kind, "terraform-plan");
    assert_eq!(at(&r, "aws_security_group.all"), vec!["AWS-SG-ALL-OPEN"]);
    assert!(at(&r, "module.db").is_empty());
    assert_eq!(at(&r, "data.aws_iam_policy_document.p"), vec!["IAM-FULL-ADMIN"], "the rendered json of a data source");

    let tf_json = r#"{"resource":{"aws_lambda_permission":{"open":{"function_name":"hook","action":"lambda:InvokeFunction","principal":"*"}}}}"#;
    let j = analyze("main.tf.json", tf_json, "auto").unwrap();
    assert_eq!((j.kind.as_str(), rules(&j)), ("terraform", vec!["AWS-LAMBDA-PUBLIC-INVOKE"]));
}

const TEMPLATE: &str = r#"AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  Encrypt:
    Type: String
Resources:
  Site:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
  SitePolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref Site
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal: "*"
            Action: s3:GetObject
            Resource: !Sub "arn:aws:s3:::${Site}/*"
  Admin:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: admin
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 3389
          ToPort: 3389
          CidrIp: 0.0.0.0/0
        - IpProtocol: tcp
          FromPort: 6379
          ToPort: 6379
          CidrIpv6: ::/0
  Db:
    Type: AWS::RDS::DBInstance
    Properties:
      PubliclyAccessible: true
      StorageEncrypted: !Ref Encrypt
  Workers:
    Type: AWS::EC2::LaunchTemplate
    Properties:
      LaunchTemplateData:
        MetadataOptions:
          HttpTokens: optional
  Ci:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              AWS: arn:aws:iam::210987654321:root
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AdministratorAccess
      Policies:
        - PolicyName: everything
          PolicyDocument:
            Statement:
              - Effect: Allow
                Action: "*"
                Resource: "*"
  Trail:
    Type: AWS::CloudTrail::Trail
    Properties:
      IsLogging: true
      IsMultiRegionTrail: true
      EnableLogFileValidation: true
"#;

#[test]
fn cloudformation_templates() {
    let r = analyze("stack.yaml", TEMPLATE, "auto").unwrap();
    assert_eq!(r.kind, "cloudformation");
    assert_eq!(at(&r, "Site (AWS::S3::Bucket)"), vec!["AWS-S3-PUBLIC-ACL"]);
    assert_eq!(at(&r, "SitePolicy"), vec!["IAM-PUBLIC"]);
    let mut sg = at(&r, "Admin (AWS::EC2::SecurityGroup)");
    sg.sort_unstable();
    assert_eq!(sg, vec!["AWS-SG-ADMIN-OPEN", "AWS-SG-DATA-OPEN"]);
    assert_eq!(at(&r, "Db (AWS::RDS::DBInstance)"), vec!["AWS-DB-PUBLIC"], "!Ref Encrypt is not resolved, so not reported as unencrypted");
    assert_eq!(at(&r, "Workers"), vec!["AWS-IMDSV1"]);
    assert_eq!(at(&r, "Ci trust policy"), vec!["IAM-CROSS-ACCOUNT-NO-EXTERNAL-ID"]);
    assert_eq!(at(&r, "Ci (AWS::IAM::Role)"), vec!["AWS-IAM-ADMIN-ATTACHED"]);
    assert_eq!(at(&r, "Ci policy everything"), vec!["IAM-FULL-ADMIN"]);
    assert!(at(&r, "Trail").is_empty());

    let json_template = r#"{"Resources":{"Url":{"Type":"AWS::Lambda::Url","Properties":{"AuthType":"NONE","TargetFunctionArn":{"Ref":"Fn"}}}}}"#;
    assert_eq!(rules(&analyze("t.json", json_template, "auto").unwrap()), vec!["AWS-LAMBDA-PUBLIC-URL"]);
}

#[test]
fn iam_exports_and_single_policies() {
    let details = serde_json::json!({
        "UserDetailList": [{ "UserName": "bob", "Arn": "arn:aws:iam::111122223333:user/bob",
            "UserPolicyList": [{ "PolicyName": "self-service", "PolicyDocument": { "Version": "2012-10-17", "Statement": [{ "Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*" }] } }],
            "AttachedManagedPolicies": [] }],
        "RoleDetailList": [{ "RoleName": "ops", "Arn": "arn:aws:iam::111122223333:role/ops",
            "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%22arn%3Aaws%3Aiam%3A%3A111122223333%3Aroot%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D",
            "RolePolicyList": [], "AttachedManagedPolicies": [{ "PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess" }] }],
        "GroupDetailList": [],
        "Policies": [{ "PolicyName": "legacy", "PolicyVersionList": [
            { "Document": { "Statement": [{ "Effect": "Allow", "Action": "s3:*", "Resource": "*" }] }, "VersionId": "v2", "IsDefaultVersion": true },
            { "Document": { "Statement": [{ "Effect": "Allow", "Action": "*", "Resource": "*" }] }, "VersionId": "v1", "IsDefaultVersion": false }] }]
    });
    let r = analyze("auth-details.json", &details.to_string(), "auto").unwrap();
    assert_eq!(r.kind, "iam-account");
    assert_eq!(at(&r, "User bob inline policy self-service"), vec!["IAM-PRIVILEGE-ESCALATION"]);
    assert_eq!(at(&r, "Role ops"), vec!["AWS-IAM-ADMIN-ATTACHED"], "a URL-encoded trust policy in the same account is fine");
    assert_eq!(at(&r, "Policy legacy"), vec!["IAM-SERVICE-ADMIN"], "only the default version counts");

    let cli = r#"{"PolicyVersion":{"Document":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]},"VersionId":"v3","IsDefaultVersion":true}}"#;
    let c = analyze("get-policy-version.json", cli, "auto").unwrap();
    assert_eq!(c.kind, "iam-policy");
    assert!(rules(&c).contains(&"IAM-NOT-ACTION"));
    assert!(c.issues[0].location.starts_with("get-policy-version.json policy version"));

    assert!(analyze("compose.yaml", "services:\n  web:\n    image: nginx\n", "auto").is_none(), "not cloud configuration");
    assert!(analyze("data.json", r#"{"name":"x"}"#, "auto").is_none());
    assert_eq!(analyze("x.json", r#"{"name":"x"}"#, "iam").unwrap().error, "No policy statements found");
}

#[test]
fn folders_are_scanned_for_cloud_configuration() {
    let dir = std::env::temp_dir().join(format!("cyberhub-iac-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("modules/net")).unwrap();
    std::fs::create_dir_all(dir.join(".terraform/providers")).unwrap();
    std::fs::write(dir.join("main.tf"), MAIN_TF).unwrap();
    std::fs::write(dir.join("modules/net/sg.tf"), "resource \"aws_security_group_rule\" \"rdp\" {\n  type = \"ingress\"\n  from_port = 3389\n  to_port = 3389\n  protocol = \"tcp\"\n  cidr_blocks = [\"0.0.0.0/0\"]\n}\n").unwrap();
    std::fs::write(dir.join("stack.yaml"), TEMPLATE).unwrap();
    std::fs::write(dir.join("package.json"), r#"{"name":"x"}"#).unwrap();
    std::fs::write(dir.join(".terraform/providers/main.tf"), MAIN_TF).unwrap();
    std::fs::write(dir.join("notes.yaml"), "title: not cloud\n").unwrap();
    let res = scan_path(&dir);
    let files: Vec<&str> = res.files.iter().map(|f| f.file.as_str()).collect();
    assert_eq!(files, vec!["main.tf", "modules/net/sg.tf", "stack.yaml"], ".terraform, package.json and other YAML are left out");
    assert_eq!(rules(&res.files[1]), vec!["AWS-SG-ADMIN-OPEN"]);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn cut_or_multibyte_configurations_never_panic() {
    // with panic = "abort" a parser panic would end the app
    for (name, text) in [("main.tf", MAIN_TF.replace("bucket", "bücket")), ("stack.yaml", TEMPLATE.replace("Bucket", "Bückét"))] {
        for (i, _) in text.char_indices().step_by(3) {
            let _ = analyze(name, &text[..i], "auto");
        }
    }
}
