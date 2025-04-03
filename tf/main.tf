terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.0"
    }
  }
}

# Configuración del proveedor AWS
provider "aws" {
  region     = "us-east-1"  # Cambia a la región que prefieras
  # NUNCA coloques credenciales directamente en el código
  # Usa variables de entorno, AWS CLI configurado o proveedores de credenciales
  # export AWS_ACCESS_KEY_ID="tu_access_key"
  # export AWS_SECRET_ACCESS_KEY="tu_secret_key"
}

# Obtenemos la IP pública actual para restringir el acceso SSH
data "http" "myip" {
  url = "https://api.ipify.org"
}

# Grupo de seguridad con acceso SSH restringido y HTTP abierto
resource "aws_security_group" "lti_secure_sg" {
  name        = "lti-secure-sg"
  description = "Grupo de seguridad con acceso SSH restringido y HTTP abierto"
  
  # SSH - Restringido a tu IP
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${chomp(data.http.myip.response_body)}/32"]
    description = "SSH access from my IP only"
  }
  
  # HTTP - Abierto para todos
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP access from anywhere"
  }
  
  # Tráfico de salida - Todo permitido
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }
  
  tags = {
    Name = "lti-secure-sg"
  }
}

# Política para gestionar instancias EC2
resource "aws_iam_policy" "ec2_management_policy" {
  name        = "lti-ec2-management-policy"
  description = "Política para crear y gestionar instancias EC2"
  
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = [
          "ec2:RunInstances",
          "ec2:DescribeInstances",
          "ec2:StartInstances",
          "ec2:StopInstances",
          "ec2:TerminateInstances",
          "ec2:CreateTags",
          "ec2:DescribeTags"
        ],
        Resource = "*"
      }
    ]
  })
}

# Política para gestionar reglas de seguridad
resource "aws_iam_policy" "security_management_policy" {
  name        = "lti-security-management-policy"
  description = "Política para configurar reglas de seguridad"
  
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = [
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:CreateSecurityGroup",
          "ec2:DeleteSecurityGroup",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSecurityGroupRules",
          "ec2:DescribeVpcs"
        ],
        Resource = "*"
      }
    ]
  })
}

# Política para gestionar buckets S3
resource "aws_iam_policy" "s3_management_policy" {
  name        = "lti-s3-management-policy"
  description = "Política para crear y gestionar buckets S3"
  
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = [
          "s3:CreateBucket",
          "s3:DeleteBucket",
          "s3:PutBucketPolicy",
          "s3:GetBucketPolicy",
          "s3:ListBucket",
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:PutObjectAcl",
          "s3:GetObjectAcl",
          "s3:PutBucketAcl",
          "s3:GetBucketAcl"
        ],
        Resource = [
          "arn:aws:s3:::lti-*",
          "arn:aws:s3:::lti-*/*"
        ]
      }
    ]
  })
}

# Política para acceder a buckets s3 que empiecen por lt
resource "aws_iam_policy" "lt_buckets_policy" {
  name        = "lti-lt-buckets-policy"
  description = "Política para acceder a buckets S3 que empiecen por lt"
  
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = [
          "s3:ListBucket",
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ],
        Resource = [
          "arn:aws:s3:::lt*",
          "arn:aws:s3:::lt*/*"
        ]
      }
    ]
  })
}

# Política para gestionar logs de actividad
resource "aws_iam_policy" "logs_management_policy" {
  name        = "lti-logs-management-policy"
  description = "Política para gestionar logs de actividad"
  
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams",
          "logs:DescribeLogGroups",
          "logs:GetLogEvents"
        ],
        Resource = "*"
      }
    ]
  })
}

# Usuario IAM para la cuenta de servicio
resource "aws_iam_user" "lti_service_account" {
  name = "lti-service-account"
  path = "/service-accounts/"
  
  tags = {
    Name        = "LTI Service Account"
    Environment = "All"
    Service     = "LTI Application"
  }
}

# Adjuntar políticas al usuario
resource "aws_iam_user_policy_attachment" "ec2_policy_attachment" {
  user       = aws_iam_user.lti_service_account.name
  policy_arn = aws_iam_policy.ec2_management_policy.arn
}

resource "aws_iam_user_policy_attachment" "security_policy_attachment" {
  user       = aws_iam_user.lti_service_account.name
  policy_arn = aws_iam_policy.security_management_policy.arn
}

resource "aws_iam_user_policy_attachment" "s3_policy_attachment" {
  user       = aws_iam_user.lti_service_account.name
  policy_arn = aws_iam_policy.s3_management_policy.arn
}

# Creación de clave de acceso para el usuario
resource "aws_iam_access_key" "lti_service_account_key" {
  user = aws_iam_user.lti_service_account.name
}

# Outputs con las credenciales (para desarrollo, en producción usar secretos)
output "service_account_id" {
  value     = aws_iam_access_key.lti_service_account_key.id
  sensitive = false
}

output "service_account_secret" {
  value     = aws_iam_access_key.lti_service_account_key.secret
  sensitive = true
}

# Rol IAM que puede ser asumido por la cuenta de servicio
resource "aws_iam_role" "lti_app_role" {
  name = "lti-application-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          AWS = aws_iam_user.lti_service_account.arn
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
  
  tags = {
    Name        = "LTI Application Role"
    Environment = "All"
    Service     = "LTI Application"
  }
}

# Adjuntar políticas al rol
resource "aws_iam_role_policy_attachment" "lt_buckets_policy_attachment" {
  role       = aws_iam_role.lti_app_role.name
  policy_arn = aws_iam_policy.lt_buckets_policy.arn
}

resource "aws_iam_role_policy_attachment" "logs_policy_attachment" {
  role       = aws_iam_role.lti_app_role.name
  policy_arn = aws_iam_policy.logs_management_policy.arn
}

# Output con el ARN del rol
output "app_role_arn" {
  value = aws_iam_role.lti_app_role.arn
  description = "ARN del rol que puede ser asumido por la aplicación LTI"
}

# Obtener AMI de Ubuntu 22.04
data "aws_ami" "ubuntu" {
  most_recent = true
  
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  
  owners = ["099720109477"] # Canonical (propietario oficial de imágenes Ubuntu)
}

# Grupo de seguridad para las instancias
resource "aws_security_group" "lti_instances_sg" {
  name        = "lti-instances-sg"
  description = "Grupo de seguridad para instancias LTI"
  
  # SSH - Restringido a tu IP
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${chomp(data.http.myip.response_body)}/32"]
    description = "SSH access from my IP only"
  }
  
  # HTTP
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  # HTTPS
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  # Puerto para Backend (3010)
  ingress {
    from_port   = 3010
    to_port     = 3010
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  # Puerto para Frontend (3000)
  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  # Permitir todo el tráfico de salida
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "lti-instances-sg"
  }
}

# Par de claves para SSH
resource "aws_key_pair" "lti_keypair" {
  key_name   = "lti-keypair"
  public_key = file("${path.module}/ssh_key.pub") # Asegúrate de tener este archivo o modifica la ruta
}

# Instancia EC2 para Backend
resource "aws_instance" "lti_backend" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t2.small"
  vpc_security_group_ids = [aws_security_group.lti_instances_sg.id]
  key_name               = aws_key_pair.lti_keypair.key_name
  
  user_data = <<-EOF
              #!/bin/bash
              apt-get update
              apt-get install -y nodejs npm
              apt-get install -y nginx
              apt-get install -y git
              
              # Instalar PM2 globalmente
              npm install -g pm2
              
              # Configurar Nginx como proxy inverso
              cat > /etc/nginx/sites-available/default << 'NGINX'
              server {
                  listen 80;
                  server_name _;
                  
                  location / {
                      proxy_pass http://localhost:3010;
                      proxy_http_version 1.1;
                      proxy_set_header Upgrade \$http_upgrade;
                      proxy_set_header Connection 'upgrade';
                      proxy_set_header Host \$host;
                      proxy_cache_bypass \$http_upgrade;
                  }
              }
              NGINX
              
              systemctl restart nginx
              EOF
  
  tags = {
    Name = "lti-backend-server"
    app  = "lti-recruiting-backend"
  }
}

# Instancia EC2 para Frontend
resource "aws_instance" "lti_frontend" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t2.small"
  vpc_security_group_ids = [aws_security_group.lti_instances_sg.id]
  key_name               = aws_key_pair.lti_keypair.key_name
  
  user_data = <<-EOF
              #!/bin/bash
              apt-get update
              apt-get install -y nodejs npm
              apt-get install -y nginx
              apt-get install -y git
              
              # Instalar PM2 globalmente
              npm install -g pm2
              
              # Configurar Nginx como servidor estático para React
              cat > /etc/nginx/sites-available/default << 'NGINX'
              server {
                  listen 80;
                  server_name _;
                  
                  location / {
                      root /var/www/html;
                      try_files \$uri \$uri/ /index.html;
                  }
              }
              NGINX
              
              systemctl restart nginx
              EOF
  
  tags = {
    Name = "lti-frontend-server"
    app  = "lti-recruiting-frontend"
  }
}

# Outputs con las IPs de las instancias
output "backend_public_ip" {
  value = aws_instance.lti_backend.public_ip
  description = "IP pública de la instancia del backend"
}

output "frontend_public_ip" {
  value = aws_instance.lti_frontend.public_ip
  description = "IP pública de la instancia del frontend"
}

# Actualizar las instancias existentes para usar el nuevo grupo de seguridad
resource "aws_network_interface_sg_attachment" "backend_sg_attachment" {
  security_group_id    = aws_security_group.lti_secure_sg.id
  network_interface_id = aws_instance.lti_backend.primary_network_interface_id
}

resource "aws_network_interface_sg_attachment" "frontend_sg_attachment" {
  security_group_id    = aws_security_group.lti_secure_sg.id
  network_interface_id = aws_instance.lti_frontend.primary_network_interface_id
}

# Output para el nuevo grupo de seguridad
output "secure_sg_id" {
  value = aws_security_group.lti_secure_sg.id
  description = "ID del grupo de seguridad con acceso SSH restringido"
}

# Bucket S3 para almacenar archivos CV
resource "aws_s3_bucket" "lti_cv_bucket" {
  bucket = "lti-recruiting-cvs"  # Los nombres de bucket deben ser únicos a nivel global
  
  tags = {
    Name        = "LTI CV Storage"
    Environment = "Production"
    Application = "LTI Recruiting"
  }
}

# Configuración de ACL para el bucket
resource "aws_s3_bucket_ownership_controls" "cv_bucket_ownership" {
  bucket = aws_s3_bucket.lti_cv_bucket.id
  
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# Configuración para bloquear acceso público al bucket (seguridad)
resource "aws_s3_bucket_public_access_block" "cv_bucket_access" {
  bucket = aws_s3_bucket.lti_cv_bucket.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Política para permitir a las instancias EC2 acceder al bucket (corregida)
resource "aws_s3_bucket_policy" "cv_bucket_policy" {
  bucket = aws_s3_bucket.lti_cv_bucket.id
  
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          AWS = aws_iam_role.lti_app_role.arn
        },
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "s3:DeleteObject"
        ],
        Resource = [
          aws_s3_bucket.lti_cv_bucket.arn,
          "${aws_s3_bucket.lti_cv_bucket.arn}/*"
        ]
      }
    ]
  })
  
  depends_on = [aws_s3_bucket_public_access_block.cv_bucket_access]
}

# Configuración CORS para permitir cargas desde el frontend
resource "aws_s3_bucket_cors_configuration" "cv_bucket_cors" {
  bucket = aws_s3_bucket.lti_cv_bucket.id
  
  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["PUT", "POST", "GET"]
    allowed_origins = ["*"]  # En producción, restringe a los dominios de tu aplicación
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
  }
}

# Configuración de ciclo de vida para gestionar archivos antiguos (corregida)
resource "aws_s3_bucket_lifecycle_configuration" "cv_bucket_lifecycle" {
  bucket = aws_s3_bucket.lti_cv_bucket.id
  
  rule {
    id = "archive-old-cvs"
    status = "Enabled"
    
    # Añadir filtro vacío para solucionar la advertencia
    filter {}
    
    transition {
      days          = 90
      storage_class = "STANDARD_IA"  # Acceso poco frecuente después de 90 días
    }
    
    transition {
      days          = 365
      storage_class = "GLACIER"  # Archivado después de 1 año
    }
  }
}

# Output para el nombre del bucket
output "cv_bucket_name" {
  value = aws_s3_bucket.lti_cv_bucket.bucket
  description = "Nombre del bucket S3 para almacenar CVs"
}

# Output para la URL del bucket
output "cv_bucket_domain_name" {
  value = aws_s3_bucket.lti_cv_bucket.bucket_regional_domain_name
  description = "URL del bucket S3 para almacenar CVs"
}
