resource "aws_securityhub_account" "security-hub" {
    count = var.enable_security_hub ? 1 : 0
}

resource "aws_securityhub_standards_subscription" "cis_v1" {
  count         = var.enable_security_hub ? 1 : 0
  depends_on    = [aws_securityhub_account.security-hub]
  standards_arn = "arn:aws:securityhub:${var.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
}

resource "aws_securityhub_standards_subscription" "cis_v1_2" {
  count         = var.enable_security_hub ? 1 : 0
  depends_on    = [aws_securityhub_account.security-hub]
  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
}

resource "aws_securityhub_standards_subscription" "cis_v1_4" {
  count         = var.enable_security_hub ? 1 : 0
  depends_on    = [aws_securityhub_account.security-hub]
  standards_arn = "arn:aws:securityhub:${var.region}::standards/cis-aws-foundations-benchmark/v/1.4.0"
}

resource "aws_securityhub_standards_subscription" "nist_800_53" {
  count         = var.enable_security_hub ? 1 : 0
  depends_on    = [aws_securityhub_account.security-hub]
  standards_arn = "arn:aws:securityhub:${var.region}::standards/nist-800-53/v/5.0.0"
}

resource "aws_securityhub_standards_subscription" "pci_321" {
  count         = var.enable_security_hub ? 1 : 0
  depends_on    = [aws_securityhub_account.security-hub]
  standards_arn = "arn:aws:securityhub:${var.region}::standards/pci-dss/v/3.2.1"
}
