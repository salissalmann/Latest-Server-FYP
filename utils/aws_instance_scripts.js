
const GenerateProviderScript = () => {
    return `provider "aws" {
        region = var.region
        access_key = var.aws_access_key
        secret_key = var.aws_secret_key
    }\n`    
}

const ConfigureVPC = () => {
    return `resource "aws_default_vpc" "default" {
        tags = {
            Name = "Default VPC"
        }
     }\n`
}

const ConfigureSecurityGroup = (inboundRules , outboundRules) => {

    let content = `resource "aws_security_group" "allow_tls" {
        name        = "allow_tls"
        description = "Allow TLS inbound traffic"
        vpc_id      = aws_default_vpc.default.id
    \n`

    inboundRules.forEach(rule => {
        content += `
        ingress {
            from_port   = ${rule.port}
            to_port     = ${rule.port}
            protocol    = "tcp"
            cidr_blocks = ["0.0.0.0/0"] 
            ipv6_cidr_blocks = ["::/0"]
        }\n`
    })

    outboundRules.forEach(rule => {
        content += `
        egress {
            from_port   = ${rule.port}
            to_port     = ${rule.port}
            protocol    = "-1"
            cidr_blocks = ["0.0.0.0/0"] 
            ipv6_cidr_blocks = ["::/0"]
        }\n`
    }
    )
    content += `}\n`
    return content
}


const ConfigureKeyPair = (keyName) => {
    return `\nresource "aws_key_pair" "terraform_key" {
        key_name   = "${keyName}"
        public_key = file("${keyName}.pub")
    }\n`
}

const ConfigureInstance = (keyName) => {
    return `resource "aws_instance" "terraform_with_key" {
        ami           = var.ami
        instance_type = var.instance_type
        key_name      = aws_key_pair.terraform_key.key_name
        tags = {
            Name = var.machine_name
        }	
        vpc_security_group_ids = [aws_security_group.allow_tls.id]


        root_block_device {
            volume_type = "gp2" 
            volume_size = var.storage_size
        }
        

        provisioner "remote-exec" {
            inline = [
                "sudo apt-get update",
                "sudo apt-get install -y nginx",
                "sudo systemctl start nginx"
            ]
    
            connection {
                type        = "ssh"
                user        = var.user
                private_key = file("${keyName}")
                host        = self.public_ip
            }
        }
    }\n`
}

const OnDemandInstance = (keyName , inbound , outbound) => {

    const fileContent = GenerateProviderScript() + ConfigureVPC() + ConfigureSecurityGroup(inbound , outbound) + ConfigureKeyPair(keyName) + ConfigureInstance(keyName)
    return fileContent
}

module.exports = {
    GenerateProviderScript,
    ConfigureVPC,
    ConfigureSecurityGroup,
    ConfigureKeyPair,
    ConfigureInstance,
    OnDemandInstance
}    
    
    


