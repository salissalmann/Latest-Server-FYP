const generateVarFileContent = ({ aws_access_key, aws_secret_key, region, machine_name, ami, instance_type, user , storage }) => {
    return `
//AWS Access Key
variable "aws_access_key" {
    default = "${aws_access_key}"
}

//AWS Secret
variable "aws_secret_key" {
    default = "${aws_secret_key}"
}

variable "region" {
    default     = "${region}"
}

//Machine Name
variable "machine_name" {
    default     = "${machine_name}"
}

//AMI
variable "ami" {
    default     = "${ami}"
}

//Instance Type
variable "instance_type" {
    default     = "${instance_type}"
}

//User
variable "user" {
    default     = "${user}"
}

//Storage
variable "storage_size" {
    default   = "${storage}"
}
`;
}

module.exports = generateVarFileContent;
