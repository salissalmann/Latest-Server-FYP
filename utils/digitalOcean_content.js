const generateVarFileContentForDO = ({ token , key_name, region, machine_name, size, storage, image, backups, monitoring }) => {
    return `
//Digital Ocean Token
variable "digitalocean_token" {
    default = "${token}"
}

//Key Name
variable "key_name" {
    default = "${key_name}"  
}

//Region
variable "region" {
    default = "${region}"
}

//Size
variable "size" {
    default = "${size}"
}

//Machine Name
variable "machine_name" {
    default = "${machine_name}"
}

//Storage
variable "storage_size" {
    default = "${storage}"
}

//Image
variable "image" {
    default = "${image}"  
}

//Backups
variable "backups" {
    default = "${backups}"  
}

//Monitoring
variable "monitoring" {
    default = "${monitoring}"  
}
`;}

module.exports = generateVarFileContentForDO;
