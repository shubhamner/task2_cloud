  provider "aws" {
  region = "ap-south-1"
  profile = "shubham"
}

//key-pair generation

resource "tls_private_key" "public_key_gen"{
	algorithm   = "RSA"
}

resource "aws_key_pair" "key_generation" {
	key_name   = "efs_task_key"
	public_key = tls_private_key.public_key_gen.public_key_openssh
	depends_on = [tls_private_key.public_key_gen]
}

//security group

resource "aws_security_group" "efs_sec_grp" {
	depends_on = [aws_key_pair.key_generation]
	name        = "efs_sec_grp"
	description = "Http ssh"

	ingress {
		description = "HTTP"
		from_port   = 80
		to_port     = 80
		protocol    = "tcp"
		cidr_blocks = ["0.0.0.0/0"]
	}

	ingress {
		description = "SSH"
		from_port   = 22
		to_port     = 22
		protocol    = "tcp"
		cidr_blocks = ["0.0.0.0/0"]
	}

	ingress{
		description = "NFS"
		from_port   = 2049
		to_port     = 2049
		protocol    = "tcp"
		cidr_blocks = ["0.0.0.0/0"]


	}
	egress {
		from_port   = 0
		to_port     = 0
		protocol    = "-1"
		cidr_blocks = ["0.0.0.0/0"]
	  
	}
	 
	tags = {
		Name = "efs_sec_grp"
	}
	  
}	
	

//ec2 instance
resource "aws_instance" "efs_web" {
	depends_on = [aws_efs_mount_target.mnt_target]
	ami           = "ami-0447a12f28fddb066"
	instance_type = "t2.micro"
	key_name      = "efs_task_key"
	//security_groups = ["efs_sec_grp"]
	associate_public_ip_address = true
	vpc_security_group_ids = ["${aws_security_group.efs_sec_grp.id}"]
    subnet_id = aws_subnet.efs_subnet.id
	availability_zone = "ap-south-1a"
	
	connection {
		type     = "ssh"
		user     = "ec2-user"
		private_key = tls_private_key.public_key_gen.private_key_pem
		host     = aws_instance.efs_web.public_ip
		
	}
	  
	provisioner "remote-exec" {
		inline = [
		   "sudo yum install httpd  php git -y",
      		"sudo systemctl restart httpd",
			"sudo yum install -y amazon-efs-utils",
		]
		
	}

	
	tags = {
		Name = "task2_os"
	}
	
}
resource "aws_subnet" "efs_subnet" {
	depends_on = [aws_security_group.efs_sec_grp]
    vpc_id = aws_security_group.efs_sec_grp.vpc_id
    availability_zone = "ap-south-1a"
    cidr_block = "172.31.48.0/20"
}	
	
//create EFS 
resource "aws_efs_file_system" "my_efs" {
	depends_on = [aws_subnet.efs_subnet]
  creation_token = "my_efs"

  tags = {
    Name = "my_efs"
  }
}

resource "aws_efs_mount_target" "mnt_target" {
	depends_on = [aws_efs_file_system.my_efs]
    file_system_id = aws_efs_file_system.my_efs.id
    subnet_id = aws_subnet.efs_subnet.id
    security_groups = [aws_security_group.efs_sec_grp.id]
}
/*
//Create EBS volume
	
resource "aws_ebs_volume" "ebs1" {
depends_on = [aws_instance.web]
  availability_zone = aws_instance.web.availability_zone
  size              = 1
  tags = {
    Name = "newebs1"
  }
  
}
*/

//Attach the volume to instance
/*
resource "aws_volume_attachment" "ebs_attach" {
	depends_on = [aws_ebs_volume.ebs1]
	device_name = "/dev/sdh"
	volume_id   = "${aws_ebs_volume.ebs1.id}"
	instance_id = "${aws_instance.web.id}"
	force_detach = true
  
}*/

// mounting 

resource "null_resource" "nullremote3"  {
	//depends_on = [aws_efs_file_system.my_efs]
	depends_on = [aws_instance.efs_web]
	
	connection {
		type     = "ssh"
		user     = "ec2-user"
		private_key = tls_private_key.public_key_gen.private_key_pem
		host     = aws_instance.efs_web.public_ip
		
	}
	  
	provisioner "remote-exec" {
		inline = [
			
			"sudo mount -t efs ${aws_efs_file_system.my_efs.id}:/ /var/www/html",
			"sudo rm -rf /var/www/html/*",
		  	"sudo git clone https://github.com/shubhamner/task2_cloud.git /var/www/html/",

		]

		/*inline = [
		  "sudo mkfs.ext4  /dev/xvdh",
		  "sudo mount  /dev/xvdh  /var/www/html",
		  "sudo rm -rf /var/www/html/*",
		  "sudo git clone https://github.com/shubhamner/task1_cloud.git /var/www/html/"
		]*/
		
	}
	
}
  resource "null_resource" "clone"  {
      provisioner "local-exec" {
        command = "git clone https://github.com/shubhamner/task2_cloud.git D:/pics/" 
        }
    }
output "myos_ip" {
	  value = aws_instance.efs_web.public_ip
	}


resource "null_resource" "nulllocal2"  {
	depends_on = [null_resource.nullremote3]
	provisioner "local-exec" {
	    command = "echo  ${aws_instance.efs_web.public_ip} > publicip.txt"
  	}
}


// Create s3 bucket

resource "aws_s3_bucket" "bucket" {
	depends_on = [null_resource.nulllocal2]
	bucket = "taskbucket18"
	acl    = "public-read"

	tags = {
		Name        = "taskbucket18"

	}
}

// Upload the image to bucket
resource "aws_s3_bucket_object" "bucket-object" {
	depends_on = [aws_s3_bucket.bucket]
	bucket = "${aws_s3_bucket.bucket.id}"
	key    = "aws-logo.png"
	source = "D:/pics/aws-logo.png"
	acl    = "public-read"	

}


// cloud front



resource "aws_cloudfront_origin_access_identity" "origin_access_identity"{
	
	comment = "origin.access.identity"
}

data "aws_iam_policy_document" "s3_policy" {
	
	statement {
		actions   = ["s3:GetObject"]
		resources = ["${aws_s3_bucket.bucket.arn}/*"]

		principals {
			type        = "AWS"
			identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"]
		}
	}

	statement{
		actions   = ["s3:ListBucket"]
		resources = ["${aws_s3_bucket.bucket.arn}"]

		principals {
			type        = "AWS"
			identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"]
		}
	}
}

resource "aws_s3_bucket_policy" "bucket_policy" {
	bucket = "${aws_s3_bucket.bucket.id}"
	policy = "${data.aws_iam_policy_document.s3_policy.json}"
}
	
locals {
	s3_origin_id = "myS3Origin"
}

resource "aws_cloudfront_distribution" "s3_distribution" {
	origin {
		domain_name = "${aws_s3_bucket.bucket.bucket_regional_domain_name}"
		origin_id   = "${local.s3_origin_id}"

		s3_origin_config {
			origin_access_identity = "${aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path}"
		}
	}
  
  	enabled = true
	is_ipv6_enabled = true
  
	default_cache_behavior {
		allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
		cached_methods   = ["GET", "HEAD"]
		target_origin_id = "${local.s3_origin_id}"

		forwarded_values {
			query_string = false

			cookies {
				forward = "none"
			}
		}

		viewer_protocol_policy = "redirect-to-https"
		min_ttl                = 0
		default_ttl            = 3600
		max_ttl                = 86400
	}
  
  
	restrictions {
		geo_restriction {
			restriction_type = "whitelist"
			locations        = ["IN","US"]
		}
	}


  
	viewer_certificate {
		cloudfront_default_certificate = true
	}
}


// add the source of cloud front

resource "null_resource" "change_code"  {

depends_on = [aws_cloudfront_distribution.s3_distribution]


  connection {
		type     = "ssh"
		user     = "ec2-user"
		private_key = tls_private_key.public_key_gen.private_key_pem
		host     = aws_instance.efs_web.public_ip
		
	}
	  
	provisioner "remote-exec" {
	inline = [
		"sudo sed -i '$ a <img src=https://${aws_cloudfront_distribution.s3_distribution.domain_name}/aws-logo.png >' /var/www/html/index.html",
		]
	}
}





//snapshot

/*
resource "aws_ebs_snapshot" "ebs_snap"{
	depends_on = [null_resource.change_code]
	volume_id   = "${aws_ebs_volume.ebs1.id}"
	description = "Snapshot"
  
	tags = {
		name = "Snap"
	}
}*/



resource "null_resource" "nulllocal1" {
	depends_on = [null_resource.change_code]

	provisioner "local-exec" {
		command = "start chrome  ${aws_instance.efs_web.public_ip}"
  	}
}	
	