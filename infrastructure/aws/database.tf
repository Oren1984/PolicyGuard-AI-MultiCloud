# RDS PostgreSQL 16 in private subnets only, with the master password
# generated and stored in Secrets Manager -- never in Terraform state as a
# plaintext variable, never in application source.

resource "random_password" "db" {
  length  = 32
  special = false
}

resource "aws_db_subnet_group" "this" {
  name       = "${var.project_name}-db-subnets"
  subnet_ids = aws_subnet.private[*].id

  tags = {
    Name = "${var.project_name}-db-subnets"
  }
}

resource "aws_db_instance" "this" {
  identifier     = "${var.project_name}-postgres"
  engine         = "postgres"
  engine_version = "16"
  instance_class = var.db_instance_class

  allocated_storage      = 20
  storage_encrypted      = true
  db_name                = var.db_name
  username               = var.db_username
  password               = random_password.db.result
  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  publicly_accessible = false
  multi_az            = false # POC simplification; enable for production
  skip_final_snapshot = true  # POC simplification; disable for production

  tags = {
    Name = "${var.project_name}-postgres"
  }
}

resource "aws_secretsmanager_secret" "db_credentials" {
  name        = "${var.project_name}/db-credentials"
  description = "PostgreSQL credentials for the PolicyGuard application (ECS reads this at task start)."
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  secret_id = aws_secretsmanager_secret.db_credentials.id
  secret_string = jsonencode({
    username = var.db_username
    password = random_password.db.result
    host     = aws_db_instance.this.address
    port     = 5432
    dbname   = var.db_name
    url      = "postgresql+psycopg://${var.db_username}:${random_password.db.result}@${aws_db_instance.this.address}:5432/${var.db_name}"
  })
}
